// SPDX-License-Identifier: MPL-2.0

//! Source-exact ATA PIO commit outbox for the persistent CSER reply slice.
//!
//! This provider owns one dedicated secondary-master ATA fixed disk.  It is
//! intentionally separate from both the primary-master CSER journal and the
//! VirtIO DMA device.  Each successful reply-backend commit is an immutable,
//! checksummed sector in a bounded append-only outbox.  A receipt is minted
//! only after the exact sector has completed `WRITE SECTORS`, `FLUSH CACHE`,
//! and readback validation.
//!
//! The receipt verifier does not copy facts out of the core challenge.  Its
//! private receipt constructor is reached only by decoding a valid outbox
//! sector, and verification compares that independently recovered record with
//! every challenge coordinate.  An absent, corrupt, ambiguous, or I/O-failed
//! observation never becomes a known-failure receipt: it remains
//! indeterminate so the causal effect continues to own its reply obligation
//! and publication slot.
//!
//! Evidence boundary: the QEMU raw-image fixture and an acknowledged emulated
//! ATA flush demonstrate the source-exact kernel/PIO/device-model path across
//! emulator restarts.  They are not evidence for physical-media power-loss
//! atomicity, controller write-cache behavior, host-filesystem durability, or
//! physical cold-boot recovery.

use cser_core::{
    ClaimId, ClaimScope, ComponentId, Digest, EffectFactChallenge, EffectFactKind, EffectId,
    EffectReceiptVerifier, EvidenceChallenge, ExecutorCoordinate, ExecutorGeneration, ExecutorId,
    ExternalOutcome, ProviderVerificationScope, REPLY_APPLY_RECEIPT_SCHEMA,
    REPLY_COMMIT_RECEIPT_SCHEMA, REPLY_DOMAIN, REPLY_EVIDENCE_PUBLICATION_ACK,
    REPLY_OBLIGATION_PUBLICATION, REPLY_RECEIPT_SCHEMA, REPLY_SETTLEMENT_RECEIPT_SCHEMA,
    REPLY_VERIFIER, ReceiptSchemaId, ReceiptVerifier, ResourceGeneration, ResourceId,
    VerificationError, VerifiedEffectObservation, VerifiedObservation, VerifierBinding,
    VerifierGeneration, VerifierIdentity,
};
use sha2::{Digest as _, Sha256};

use super::core_pio_journal::{
    AtaJournalFixture, AtaPioDisk, AtaPioError, SECTOR_BYTES, SectorBackend,
};
use super::core_production_registry::{
    PRODUCTION_WORLD, REPLY_APPLY_IMPLEMENTATION_DIGEST, REPLY_COMMIT_IMPLEMENTATION_DIGEST,
    REPLY_RECEIPT_IMPLEMENTATION_DIGEST, REPLY_SETTLEMENT_IMPLEMENTATION_DIGEST,
    STANDARD_REPLY_PROVIDER,
};
use super::core_reply_adapter::ReplyPlan;

// LBA 0 remains untouched.  The bounded append-only shape turns capacity and
// ambiguous media damage into explicit backpressure rather than overwriting a
// possibly committed reply.
const FIRST_OUTBOX_LBA: u32 = 1;
const OUTBOX_SLOTS: u32 = 128;
const FIRST_DELIVERY_LBA: u32 = FIRST_OUTBOX_LBA + OUTBOX_SLOTS;
const DELIVERY_SLOTS: u32 = 128;
const REQUIRED_OUTBOX_SECTORS: u32 = FIRST_DELIVERY_LBA + DELIVERY_SLOTS;

const RECORD_MAGIC: [u8; 8] = *b"CSEROUT\0";
const RECORD_VERSION: u16 = 3;
const RECORD_LEN: u16 = 208;
const RECORD_STATE_COMMITTED: u32 = 1;

const CHECKSUM_OFFSET: usize = 176;
const CHECKSUM_END: usize = 208;

const DELIVERY_MAGIC: [u8; 8] = *b"CSERDLV\0";
const DELIVERY_VERSION: u16 = 1;
const DELIVERY_RECORD_LEN: u16 = 288;
const DELIVERY_STATE_APPLIED: u32 = 1;
const DELIVERY_STATE_ACKNOWLEDGED: u32 = 2;
const DELIVERY_SOURCE_COMMIT: u32 = 1;
const DELIVERY_SOURCE_ATOMIC_ARM: u32 = 2;
const DELIVERY_SOURCE_APPLY: u32 = 3;
const DELIVERY_CHECKSUM_OFFSET: usize = 256;
const DELIVERY_CHECKSUM_END: usize = 288;

/// Stable reply identity below an exact CSER effect.
///
/// `sequence` is the publication/outbox identity chosen before the external
/// commit.  It is deliberately independent of an OSTD task address or a boot
/// allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyOutboxIdentity {
    effect: EffectId,
    sequence: u64,
}

impl ReplyOutboxIdentity {
    pub(crate) const fn new(effect: EffectId, sequence: u64) -> Option<Self> {
        if sequence == 0 {
            None
        } else {
            Some(Self { effect, sequence })
        }
    }

    pub(crate) const fn effect(self) -> EffectId {
        self.effect
    }

    pub(crate) const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// Complete immutable identity written for one external reply commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplyCommitKey {
    reply: ReplyOutboxIdentity,
    component: ComponentId,
    actor: ExecutorCoordinate,
    authority_generation: u64,
    intent_nonce: u64,
    operation: Digest,
}

impl ReplyCommitKey {
    fn from_challenge(
        challenge: &EffectFactChallenge,
        reply_sequence: u64,
    ) -> Result<Self, ReplyOutboxRequestError> {
        let Some(reply) = ReplyOutboxIdentity::new(challenge.effect(), reply_sequence) else {
            return Err(ReplyOutboxRequestError::InvalidReplySequence);
        };
        let component = challenge.component();
        if challenge.kind() != EffectFactKind::CommitOutcome
            || challenge.domain() != REPLY_DOMAIN
            || challenge.obligation() != REPLY_OBLIGATION_PUBLICATION
            || challenge.predecessor().is_some()
            || challenge.expected_verifier() != REPLY_VERIFIER
            || challenge.expected_receipt_schema() != REPLY_COMMIT_RECEIPT_SCHEMA
        {
            return Err(ReplyOutboxRequestError::WrongChallenge);
        }
        if challenge.generation() == 0 || challenge.nonce() == 0 || challenge.operation().is_zero()
        {
            return Err(ReplyOutboxRequestError::InvalidChallengeIdentity);
        }
        Ok(Self {
            reply,
            component,
            actor: challenge.actor(),
            authority_generation: challenge.generation(),
            intent_nonce: challenge.nonce(),
            operation: challenge.operation(),
        })
    }
}

/// A source-exact committed record returned only after sector validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyCommitReceipt {
    key: ReplyCommitKey,
    payload_digest: Digest,
    commit_generation: u64,
    record_checksum: Digest,
}

impl ReplyCommitReceipt {
    pub(crate) const fn reply(self) -> ReplyOutboxIdentity {
        self.key.reply
    }

    pub(crate) const fn actor(self) -> ExecutorCoordinate {
        self.key.actor
    }

    pub(crate) const fn component(self) -> ComponentId {
        self.key.component
    }

    pub(crate) const fn authority_generation(self) -> u64 {
        self.key.authority_generation
    }

    pub(crate) const fn intent_nonce(self) -> u64 {
        self.key.intent_nonce
    }

    pub(crate) const fn operation(self) -> Digest {
        self.key.operation
    }

    pub(crate) const fn payload_digest(self) -> Digest {
        self.payload_digest
    }

    pub(crate) const fn commit_generation(self) -> u64 {
        self.commit_generation
    }

    pub(crate) const fn record_checksum(self) -> Digest {
        self.record_checksum
    }

    fn self_authenticates(self) -> bool {
        if self.payload_digest.is_zero()
            || self.record_checksum.is_zero()
            || self.commit_generation == 0
        {
            return false;
        }
        let record = ReplyRecord {
            key: self.key,
            payload_digest: self.payload_digest,
            commit_generation: self.commit_generation,
        };
        record.checksum() == self.record_checksum
    }
}

/// Failure to form a valid source commit request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyOutboxRequestError {
    InvalidReplySequence,
    InvalidPayloadDigest,
    InvalidChallengeIdentity,
    WrongChallenge,
}

/// Disk operation whose failure leaves commit outcome unknowable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyOutboxOperation {
    Read,
    Write,
    Flush,
    Readback,
}

/// Exact corruption which can safely be attributed to the requested reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyOutboxCorruption {
    TargetRecord {
        slot: u32,
    },
    IdentityMismatch {
        slot: u32,
    },
    ConflictingRecords {
        first_slot: u32,
        second_slot: u32,
    },
    ConflictingPayload {
        committed: Digest,
        requested: Digest,
    },
}

/// An observation which cannot establish absence, success, or known failure.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReplyOutboxIndeterminate<E> {
    Storage {
        operation: ReplyOutboxOperation,
        slot: Option<u32>,
        error: E,
    },
    AmbiguousCorruption {
        slot: u32,
    },
    PublishReadbackMismatch {
        slot: u32,
    },
}

/// Exact post-restart observation for one reply identity.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReplyCommitInspection<E> {
    Absent,
    Committed(ReplyCommitReceipt),
    Corrupt(ReplyOutboxCorruption),
    Indeterminate(ReplyOutboxIndeterminate<E>),
}

/// Durable source from which one settlement apply publication is
/// reconstructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyApplySource {
    /// The ordinary commit-outbox record is present and source-exact.
    Committed(Digest),
    /// Atomic component arm survived, but its commit bearer and outbox write
    /// did not. The successor materializes the deterministic reply from the
    /// journaled component operation.
    AtomicArmIndeterminate(Digest),
}

impl ReplyApplySource {
    pub(crate) const fn predecessor_digest(self) -> Digest {
        match self {
            Self::Committed(digest) | Self::AtomicArmIndeterminate(digest) => digest,
        }
    }

    fn parts(self) -> Option<(u32, Digest)> {
        match self {
            Self::Committed(digest) if !digest.is_zero() => Some((DELIVERY_SOURCE_COMMIT, digest)),
            Self::AtomicArmIndeterminate(digest) if !digest.is_zero() => {
                Some((DELIVERY_SOURCE_ATOMIC_ARM, digest))
            }
            Self::Committed(_) | Self::AtomicArmIndeterminate(_) => None,
        }
    }
}

/// Source-exact durable apply publication recovered from the reply disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyApplyRecord {
    record: ReplyDeliveryRecord,
}

impl ReplyApplyRecord {
    pub(crate) const fn reply(self) -> ReplyOutboxIdentity {
        self.record.key.reply
    }

    pub(crate) const fn semantic_digest(self) -> Digest {
        self.record.semantic_digest
    }

    pub(crate) const fn record_checksum(self) -> Digest {
        self.record.record_checksum
    }

    pub(crate) fn source(self) -> ReplyApplySource {
        match self.record.source_kind {
            DELIVERY_SOURCE_COMMIT => ReplyApplySource::Committed(self.record.predecessor),
            DELIVERY_SOURCE_ATOMIC_ARM => {
                ReplyApplySource::AtomicArmIndeterminate(self.record.predecessor)
            }
            _ => unreachable!("validated apply records have a known source"),
        }
    }

    pub(crate) fn matches_plan(self, plan: ReplyPlan) -> bool {
        self.record.kind == ReplyDeliveryKind::Applied
            && self.record.key == ReplyDeliveryKey::from_plan(plan)
            && self.record.semantic_digest == plan.apply_receipt_digest()
            && self.record.self_authenticates()
    }
}

/// Source-exact durable client acknowledgement recovered from the reply disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyAckRecord {
    record: ReplyDeliveryRecord,
}

impl ReplyAckRecord {
    pub(crate) const fn reply(self) -> ReplyOutboxIdentity {
        self.record.key.reply
    }

    pub(crate) const fn semantic_digest(self) -> Digest {
        self.record.semantic_digest
    }

    pub(crate) const fn apply_record_checksum(self) -> Digest {
        self.record.predecessor
    }

    pub(crate) const fn record_checksum(self) -> Digest {
        self.record.record_checksum
    }

    pub(crate) fn matches_plan(self, plan: ReplyPlan, apply: ReplyApplyRecord) -> bool {
        self.record.kind == ReplyDeliveryKind::Acknowledged
            && self.record.key == ReplyDeliveryKey::from_plan(plan)
            && self.record.semantic_digest == plan.acknowledgement_digest()
            && self.record.predecessor == apply.record_checksum()
            && self.record.self_authenticates()
    }
}

/// Exact restart observation of the durable settlement delivery protocol.
// The complete identity and digest chain remains inline so boot recovery does
// not allocate while deciding whether wake or reuse is admissible. The enum is
// bounded by two fixed records and never crosses the client ABI.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReplyDeliveryInspection<E> {
    Absent,
    Applied(ReplyApplyRecord),
    Acknowledged {
        apply: ReplyApplyRecord,
        acknowledgement: ReplyAckRecord,
    },
    Corrupt(ReplyDeliveryCorruption),
    Indeterminate(ReplyOutboxIndeterminate<E>),
}

/// Corruption attributable to one stable reply delivery identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyDeliveryCorruption {
    TargetRecord { slot: u32 },
    ConflictingApply { first_slot: u32, second_slot: u32 },
    ConflictingAcknowledgement { first_slot: u32, second_slot: u32 },
    AcknowledgementWithoutApply { slot: u32 },
    AcknowledgementPredecessorMismatch { slot: u32 },
}

/// Failure to append or recover one delivery-protocol record.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReplyDeliveryError<E> {
    InvalidSource,
    PlanConflict,
    ApplyAbsent,
    Corrupt(ReplyDeliveryCorruption),
    Indeterminate(ReplyOutboxIndeterminate<E>),
    Full,
    GenerationExhausted,
}

/// Failure to publish a new immutable commit record.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReplyOutboxCommitError<E> {
    Request(ReplyOutboxRequestError),
    Corrupt(ReplyOutboxCorruption),
    Indeterminate(ReplyOutboxIndeterminate<E>),
    Full,
    GenerationExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplyRecord {
    key: ReplyCommitKey,
    payload_digest: Digest,
    commit_generation: u64,
}

impl ReplyRecord {
    fn encode(self) -> [u8; SECTOR_BYTES] {
        let mut bytes = [0u8; SECTOR_BYTES];
        bytes[..8].copy_from_slice(&RECORD_MAGIC);
        bytes[8..10].copy_from_slice(&RECORD_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&RECORD_LEN.to_le_bytes());
        bytes[12..16].copy_from_slice(&RECORD_STATE_COMMITTED.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.commit_generation.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.key.reply.effect().operation().get().to_le_bytes());
        bytes[32..40].copy_from_slice(&self.key.reply.effect().sequence().to_le_bytes());
        bytes[40..48].copy_from_slice(&self.key.reply.sequence().to_le_bytes());
        bytes[48..56].copy_from_slice(&self.key.actor.executor().get().to_le_bytes());
        bytes[56..64].copy_from_slice(&self.key.actor.generation().get().to_le_bytes());
        bytes[64..72].copy_from_slice(&self.key.authority_generation.to_le_bytes());
        bytes[72..80].copy_from_slice(&self.key.intent_nonce.to_le_bytes());
        bytes[80..112].copy_from_slice(&self.key.operation.bytes());
        bytes[112..144].copy_from_slice(&self.payload_digest.bytes());
        bytes[144..148].copy_from_slice(&self.key.component.get().to_le_bytes());
        // 148..176 is reserved and must remain zero.  The digest covers the
        // exact v3 framing plus every reserved and trailing byte.  Older records
        // is intentionally not inferred or upgraded because it did not bind a
        // component identity.
        let checksum = sector_checksum(bytes);
        bytes[CHECKSUM_OFFSET..CHECKSUM_END].copy_from_slice(&checksum.bytes());
        bytes
    }

    fn checksum(self) -> Digest {
        let bytes = self.encode();
        let mut raw = [0u8; SECTOR_BYTES];
        raw.copy_from_slice(&bytes);
        raw[CHECKSUM_OFFSET..CHECKSUM_END].fill(0);
        sector_checksum(raw)
    }

    fn decode(bytes: &[u8; SECTOR_BYTES]) -> SlotInspection {
        if bytes.iter().all(|byte| *byte == 0) {
            return SlotInspection::Blank;
        }
        let Some(key) = decode_structural_key(bytes) else {
            return SlotInspection::UnknownCorrupt;
        };
        if read_u64(bytes, 16) == 0
            || bytes[112..144].iter().all(|byte| *byte == 0)
            || bytes[148..CHECKSUM_OFFSET].iter().any(|byte| *byte != 0)
            || bytes[CHECKSUM_END..].iter().any(|byte| *byte != 0)
        {
            return SlotInspection::TargetCorrupt(key.reply);
        }

        let mut expected_bytes = *bytes;
        expected_bytes[CHECKSUM_OFFSET..CHECKSUM_END].fill(0);
        let expected = sector_checksum(expected_bytes);
        let stored = Digest::new(read_array_32(bytes, CHECKSUM_OFFSET));
        if stored.is_zero() || stored != expected {
            return SlotInspection::TargetCorrupt(key.reply);
        }

        SlotInspection::Valid(ReplyCommitReceipt {
            key,
            payload_digest: Digest::new(read_array_32(bytes, 112)),
            commit_generation: read_u64(bytes, 16),
            record_checksum: stored,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotInspection {
    Blank,
    Valid(ReplyCommitReceipt),
    TargetCorrupt(ReplyOutboxIdentity),
    UnknownCorrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplyDeliveryKind {
    Applied,
    Acknowledged,
}

impl ReplyDeliveryKind {
    const fn state(self) -> u32 {
        match self {
            Self::Applied => DELIVERY_STATE_APPLIED,
            Self::Acknowledged => DELIVERY_STATE_ACKNOWLEDGED,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplyDeliveryKey {
    reply: ReplyOutboxIdentity,
    component: ComponentId,
    claim: ClaimId,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    publication_sequence: u64,
    value: u64,
    intent_digest: Digest,
    payload_digest: Digest,
}

impl ReplyDeliveryKey {
    fn from_plan(plan: ReplyPlan) -> Self {
        let coordinate = plan.coordinate();
        Self {
            reply: ReplyOutboxIdentity::new(coordinate.effect(), plan.publication_sequence())
                .expect("validated reply plans have a non-zero publication sequence"),
            component: coordinate.component(),
            claim: coordinate.claim(),
            resource: coordinate.resource(),
            resource_generation: coordinate.resource_generation(),
            publication_sequence: plan.publication_sequence(),
            value: plan.value(),
            intent_digest: plan.intent_digest(),
            payload_digest: plan.payload_digest(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplyDeliveryRecord {
    kind: ReplyDeliveryKind,
    generation: u64,
    key: ReplyDeliveryKey,
    source_kind: u32,
    predecessor: Digest,
    semantic_digest: Digest,
    record_checksum: Digest,
}

impl ReplyDeliveryRecord {
    fn applied(generation: u64, plan: ReplyPlan, source: ReplyApplySource) -> Option<Self> {
        let (source_kind, predecessor) = source.parts()?;
        let mut record = Self {
            kind: ReplyDeliveryKind::Applied,
            generation,
            key: ReplyDeliveryKey::from_plan(plan),
            source_kind,
            predecessor,
            semantic_digest: plan.apply_receipt_digest(),
            record_checksum: Digest::ZERO,
        };
        record.record_checksum = delivery_sector_checksum(record.encode());
        Some(record)
    }

    fn acknowledged(generation: u64, plan: ReplyPlan, apply: ReplyApplyRecord) -> Option<Self> {
        if !apply.matches_plan(plan) {
            return None;
        }
        let mut record = Self {
            kind: ReplyDeliveryKind::Acknowledged,
            generation,
            key: ReplyDeliveryKey::from_plan(plan),
            source_kind: DELIVERY_SOURCE_APPLY,
            predecessor: apply.record_checksum(),
            semantic_digest: plan.acknowledgement_digest(),
            record_checksum: Digest::ZERO,
        };
        record.record_checksum = delivery_sector_checksum(record.encode());
        Some(record)
    }

    fn encode(self) -> [u8; SECTOR_BYTES] {
        let mut bytes = [0u8; SECTOR_BYTES];
        bytes[..8].copy_from_slice(&DELIVERY_MAGIC);
        bytes[8..10].copy_from_slice(&DELIVERY_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&DELIVERY_RECORD_LEN.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.kind.state().to_le_bytes());
        bytes[16..24].copy_from_slice(&self.generation.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.key.reply.effect().operation().get().to_le_bytes());
        bytes[32..40].copy_from_slice(&self.key.reply.effect().sequence().to_le_bytes());
        bytes[40..48].copy_from_slice(&self.key.reply.sequence().to_le_bytes());
        bytes[48..52].copy_from_slice(&self.key.component.get().to_le_bytes());
        bytes[56..64].copy_from_slice(&self.key.claim.get().to_le_bytes());
        bytes[64..72].copy_from_slice(&self.key.resource.get().to_le_bytes());
        bytes[72..80].copy_from_slice(&self.key.resource_generation.get().to_le_bytes());
        bytes[80..88].copy_from_slice(&self.key.publication_sequence.to_le_bytes());
        bytes[88..96].copy_from_slice(&self.key.value.to_le_bytes());
        bytes[96..128].copy_from_slice(&self.key.intent_digest.bytes());
        bytes[128..160].copy_from_slice(&self.key.payload_digest.bytes());
        bytes[160..164].copy_from_slice(&self.source_kind.to_le_bytes());
        bytes[192..224].copy_from_slice(&self.predecessor.bytes());
        bytes[224..256].copy_from_slice(&self.semantic_digest.bytes());
        bytes[DELIVERY_CHECKSUM_OFFSET..DELIVERY_CHECKSUM_END]
            .copy_from_slice(&self.record_checksum.bytes());
        bytes
    }

    fn self_authenticates(self) -> bool {
        if self.generation == 0
            || self.predecessor.is_zero()
            || self.semantic_digest.is_zero()
            || self.record_checksum.is_zero()
            || self.key.intent_digest.is_zero()
            || self.key.payload_digest.is_zero()
            || self.key.publication_sequence == 0
        {
            return false;
        }
        let mut without_checksum = self;
        without_checksum.record_checksum = Digest::ZERO;
        delivery_sector_checksum(without_checksum.encode()) == self.record_checksum
    }

    fn decode(bytes: &[u8; SECTOR_BYTES]) -> DeliverySlotInspection {
        if bytes.iter().all(|byte| *byte == 0) {
            return DeliverySlotInspection::Blank;
        }
        let Some((kind, key)) = decode_delivery_structural_key(bytes) else {
            return DeliverySlotInspection::UnknownCorrupt;
        };
        let generation = read_u64(bytes, 16);
        let source_kind = read_u32(bytes, 160);
        let predecessor = Digest::new(read_array_32(bytes, 192));
        let semantic_digest = Digest::new(read_array_32(bytes, 224));
        let record_checksum = Digest::new(read_array_32(bytes, DELIVERY_CHECKSUM_OFFSET));
        let reserved_valid = bytes[52..56].iter().all(|byte| *byte == 0)
            && bytes[164..192].iter().all(|byte| *byte == 0)
            && bytes[DELIVERY_CHECKSUM_END..].iter().all(|byte| *byte == 0);
        let source_valid = match kind {
            ReplyDeliveryKind::Applied => {
                matches!(
                    source_kind,
                    DELIVERY_SOURCE_COMMIT | DELIVERY_SOURCE_ATOMIC_ARM
                )
            }
            ReplyDeliveryKind::Acknowledged => source_kind == DELIVERY_SOURCE_APPLY,
        };
        let record = Self {
            kind,
            generation,
            key,
            source_kind,
            predecessor,
            semantic_digest,
            record_checksum,
        };
        if !reserved_valid || !source_valid || !record.self_authenticates() {
            return DeliverySlotInspection::TargetCorrupt(key.reply);
        }
        DeliverySlotInspection::Valid(record)
    }
}

// Sector decode is a fixed-size boot path; retaining the decoded record inline
// avoids one allocation per scanned sector.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeliverySlotInspection {
    Blank,
    Valid(ReplyDeliveryRecord),
    TargetCorrupt(ReplyOutboxIdentity),
    UnknownCorrupt,
}

fn decode_delivery_structural_key(
    bytes: &[u8; SECTOR_BYTES],
) -> Option<(ReplyDeliveryKind, ReplyDeliveryKey)> {
    if bytes[..8] != DELIVERY_MAGIC
        || read_u16(bytes, 8) != DELIVERY_VERSION
        || read_u16(bytes, 10) != DELIVERY_RECORD_LEN
    {
        return None;
    }
    let kind = match read_u32(bytes, 12) {
        DELIVERY_STATE_APPLIED => ReplyDeliveryKind::Applied,
        DELIVERY_STATE_ACKNOWLEDGED => ReplyDeliveryKind::Acknowledged,
        _ => return None,
    };
    let operation = cser_core::OperationId::new(read_u64(bytes, 24)).ok()?;
    let effect = EffectId::new(operation, read_u64(bytes, 32)).ok()?;
    let reply = ReplyOutboxIdentity::new(effect, read_u64(bytes, 40))?;
    let component = ComponentId::new(read_u32(bytes, 48)).ok()?;
    let claim = ClaimId::new(read_u64(bytes, 56)).ok()?;
    let resource = ResourceId::new(read_u64(bytes, 64)).ok()?;
    let resource_generation = ResourceGeneration::new(read_u64(bytes, 72)).ok()?;
    let publication_sequence = read_u64(bytes, 80);
    let intent_digest = Digest::new(read_array_32(bytes, 96));
    let payload_digest = Digest::new(read_array_32(bytes, 128));
    if publication_sequence == 0
        || reply.sequence() != publication_sequence
        || intent_digest.is_zero()
        || payload_digest.is_zero()
    {
        return None;
    }
    Some((
        kind,
        ReplyDeliveryKey {
            reply,
            component,
            claim,
            resource,
            resource_generation,
            publication_sequence,
            value: read_u64(bytes, 88),
            intent_digest,
            payload_digest,
        },
    ))
}

fn decode_structural_key(bytes: &[u8; SECTOR_BYTES]) -> Option<ReplyCommitKey> {
    if bytes[..8] != RECORD_MAGIC
        || read_u16(bytes, 8) != RECORD_VERSION
        || read_u16(bytes, 10) != RECORD_LEN
        || read_u32(bytes, 12) != RECORD_STATE_COMMITTED
    {
        return None;
    }
    let operation_id = cser_core::OperationId::new(read_u64(bytes, 24)).ok()?;
    let effect = EffectId::new(operation_id, read_u64(bytes, 32)).ok()?;
    let reply = ReplyOutboxIdentity::new(effect, read_u64(bytes, 40))?;
    let executor = ExecutorId::new(read_u64(bytes, 48)).ok()?;
    let actor =
        ExecutorCoordinate::new(executor, ExecutorGeneration::new(read_u64(bytes, 56)).ok()?);
    let authority_generation = read_u64(bytes, 64);
    let intent_nonce = read_u64(bytes, 72);
    let operation = Digest::new(read_array_32(bytes, 80));
    let component = ComponentId::new(read_u32(bytes, 144)).ok()?;
    if authority_generation == 0 || intent_nonce == 0 || operation.is_zero() {
        return None;
    }
    Some(ReplyCommitKey {
        reply,
        component,
        actor,
        authority_generation,
        intent_nonce,
        operation,
    })
}

struct CleanScan {
    matching: Option<(u32, ReplyCommitReceipt)>,
    first_blank: Option<u32>,
    max_generation: u64,
}

struct CleanDeliveryScan {
    apply: Option<(u32, ReplyApplyRecord)>,
    acknowledgement: Option<(u32, ReplyAckRecord)>,
    first_blank: Option<u32>,
    max_generation: u64,
}

enum ScanResult<E> {
    Clean(CleanScan),
    Corrupt(ReplyOutboxCorruption),
    Indeterminate(ReplyOutboxIndeterminate<E>),
}

// The scan result is stack-local and bounded by exactly one APPLY/ACK pair.
#[allow(clippy::large_enum_variant)]
enum DeliveryScanResult<E> {
    Clean(CleanDeliveryScan),
    Corrupt(ReplyDeliveryCorruption),
    Indeterminate(ReplyOutboxIndeterminate<E>),
}

/// Generic bounded outbox over the same fixed-sector primitive used by the
/// concrete ATA transport.
#[derive(Debug)]
struct ReplyOutbox<B> {
    backend: B,
}

impl<B> ReplyOutbox<B>
where
    B: SectorBackend,
{
    fn open(backend: B) -> Result<Self, ReplyOutboxOpenError> {
        let sectors = backend.sector_count();
        if sectors < REQUIRED_OUTBOX_SECTORS {
            return Err(ReplyOutboxOpenError::DeviceTooSmall {
                sectors,
                required: REQUIRED_OUTBOX_SECTORS,
            });
        }
        Ok(Self { backend })
    }

    fn inspect(&mut self, reply: ReplyOutboxIdentity) -> ReplyCommitInspection<B::Error> {
        match self.scan(reply) {
            ScanResult::Clean(scan) => scan
                .matching
                .map_or(ReplyCommitInspection::Absent, |(_, r)| {
                    ReplyCommitInspection::Committed(r)
                }),
            ScanResult::Corrupt(corruption) => ReplyCommitInspection::Corrupt(corruption),
            ScanResult::Indeterminate(reason) => ReplyCommitInspection::Indeterminate(reason),
        }
    }

    fn inspect_delivery(
        &mut self,
        reply: ReplyOutboxIdentity,
    ) -> ReplyDeliveryInspection<B::Error> {
        match self.scan_delivery(reply) {
            DeliveryScanResult::Clean(scan) => match (scan.apply, scan.acknowledgement) {
                (None, None) => ReplyDeliveryInspection::Absent,
                (Some((_, apply)), None) => ReplyDeliveryInspection::Applied(apply),
                (Some((_, apply)), Some((_, acknowledgement))) => {
                    ReplyDeliveryInspection::Acknowledged {
                        apply,
                        acknowledgement,
                    }
                }
                (None, Some((slot, _))) => ReplyDeliveryInspection::Corrupt(
                    ReplyDeliveryCorruption::AcknowledgementWithoutApply { slot },
                ),
            },
            DeliveryScanResult::Corrupt(corruption) => ReplyDeliveryInspection::Corrupt(corruption),
            DeliveryScanResult::Indeterminate(reason) => {
                ReplyDeliveryInspection::Indeterminate(reason)
            }
        }
    }

    fn record_apply(
        &mut self,
        plan: ReplyPlan,
        source: ReplyApplySource,
    ) -> Result<ReplyApplyRecord, ReplyDeliveryError<B::Error>> {
        if source.parts().is_none() {
            return Err(ReplyDeliveryError::InvalidSource);
        }
        let key = ReplyDeliveryKey::from_plan(plan);
        let scan = match self.scan_delivery(key.reply) {
            DeliveryScanResult::Clean(scan) => scan,
            DeliveryScanResult::Corrupt(corruption) => {
                return Err(ReplyDeliveryError::Corrupt(corruption));
            }
            DeliveryScanResult::Indeterminate(reason) => {
                return Err(ReplyDeliveryError::Indeterminate(reason));
            }
        };
        if let Some((_, existing)) = scan.apply {
            if existing.matches_plan(plan) && existing.source() == source {
                return Ok(existing);
            }
            return Err(ReplyDeliveryError::PlanConflict);
        }
        if scan.acknowledgement.is_some() {
            return Err(ReplyDeliveryError::PlanConflict);
        }
        let Some(slot) = scan.first_blank else {
            return Err(ReplyDeliveryError::Full);
        };
        let generation = scan
            .max_generation
            .checked_add(1)
            .ok_or(ReplyDeliveryError::GenerationExhausted)?;
        let record = ReplyDeliveryRecord::applied(generation, plan, source)
            .ok_or(ReplyDeliveryError::InvalidSource)?;
        self.append_delivery(slot, record)?;
        Ok(ReplyApplyRecord { record })
    }

    fn record_acknowledgement(
        &mut self,
        plan: ReplyPlan,
        apply: ReplyApplyRecord,
    ) -> Result<ReplyAckRecord, ReplyDeliveryError<B::Error>> {
        if !apply.matches_plan(plan) {
            return Err(ReplyDeliveryError::PlanConflict);
        }
        let key = ReplyDeliveryKey::from_plan(plan);
        let scan = match self.scan_delivery(key.reply) {
            DeliveryScanResult::Clean(scan) => scan,
            DeliveryScanResult::Corrupt(corruption) => {
                return Err(ReplyDeliveryError::Corrupt(corruption));
            }
            DeliveryScanResult::Indeterminate(reason) => {
                return Err(ReplyDeliveryError::Indeterminate(reason));
            }
        };
        let Some((_, persisted_apply)) = scan.apply else {
            return Err(ReplyDeliveryError::ApplyAbsent);
        };
        if persisted_apply != apply {
            return Err(ReplyDeliveryError::PlanConflict);
        }
        if let Some((_, existing)) = scan.acknowledgement {
            if existing.matches_plan(plan, apply) {
                return Ok(existing);
            }
            return Err(ReplyDeliveryError::PlanConflict);
        }
        let Some(slot) = scan.first_blank else {
            return Err(ReplyDeliveryError::Full);
        };
        let generation = scan
            .max_generation
            .checked_add(1)
            .ok_or(ReplyDeliveryError::GenerationExhausted)?;
        let record = ReplyDeliveryRecord::acknowledged(generation, plan, apply)
            .ok_or(ReplyDeliveryError::PlanConflict)?;
        self.append_delivery(slot, record)?;
        Ok(ReplyAckRecord { record })
    }

    fn append_delivery(
        &mut self,
        slot: u32,
        record: ReplyDeliveryRecord,
    ) -> Result<(), ReplyDeliveryError<B::Error>> {
        let encoded = record.encode();
        let lba = delivery_slot_lba(slot);
        if let Err(error) = self.backend.write_sector(lba, &encoded) {
            return Err(ReplyDeliveryError::Indeterminate(
                ReplyOutboxIndeterminate::Storage {
                    operation: ReplyOutboxOperation::Write,
                    slot: Some(slot),
                    error,
                },
            ));
        }
        if let Err(error) = self.backend.flush() {
            return Err(ReplyDeliveryError::Indeterminate(
                ReplyOutboxIndeterminate::Storage {
                    operation: ReplyOutboxOperation::Flush,
                    slot: Some(slot),
                    error,
                },
            ));
        }
        let mut readback = [0u8; SECTOR_BYTES];
        if let Err(error) = self.backend.read_sector(lba, &mut readback) {
            return Err(ReplyDeliveryError::Indeterminate(
                ReplyOutboxIndeterminate::Storage {
                    operation: ReplyOutboxOperation::Readback,
                    slot: Some(slot),
                    error,
                },
            ));
        }
        if readback != encoded {
            return Err(ReplyDeliveryError::Indeterminate(
                ReplyOutboxIndeterminate::PublishReadbackMismatch { slot },
            ));
        }
        match ReplyDeliveryRecord::decode(&readback) {
            DeliverySlotInspection::Valid(observed) if observed == record => Ok(()),
            DeliverySlotInspection::Blank
            | DeliverySlotInspection::Valid(_)
            | DeliverySlotInspection::TargetCorrupt(_)
            | DeliverySlotInspection::UnknownCorrupt => Err(ReplyDeliveryError::Indeterminate(
                ReplyOutboxIndeterminate::PublishReadbackMismatch { slot },
            )),
        }
    }

    fn commit_exact(
        &mut self,
        key: ReplyCommitKey,
        payload_digest: Digest,
    ) -> Result<ReplyCommitReceipt, ReplyOutboxCommitError<B::Error>> {
        if payload_digest.is_zero() {
            return Err(ReplyOutboxCommitError::Request(
                ReplyOutboxRequestError::InvalidPayloadDigest,
            ));
        }
        let scan = match self.scan(key.reply) {
            ScanResult::Clean(scan) => scan,
            ScanResult::Corrupt(corruption) => {
                return Err(ReplyOutboxCommitError::Corrupt(corruption));
            }
            ScanResult::Indeterminate(reason) => {
                return Err(ReplyOutboxCommitError::Indeterminate(reason));
            }
        };
        if let Some((slot, committed)) = scan.matching {
            if committed.key != key {
                return Err(ReplyOutboxCommitError::Corrupt(
                    ReplyOutboxCorruption::IdentityMismatch { slot },
                ));
            }
            if committed.payload_digest != payload_digest {
                return Err(ReplyOutboxCommitError::Corrupt(
                    ReplyOutboxCorruption::ConflictingPayload {
                        committed: committed.payload_digest,
                        requested: payload_digest,
                    },
                ));
            }
            return Ok(committed);
        }
        let Some(slot) = scan.first_blank else {
            return Err(ReplyOutboxCommitError::Full);
        };
        let commit_generation = scan
            .max_generation
            .checked_add(1)
            .ok_or(ReplyOutboxCommitError::GenerationExhausted)?;
        let record = ReplyRecord {
            key,
            payload_digest,
            commit_generation,
        };
        let encoded = record.encode();
        let lba = slot_lba(slot);
        if let Err(error) = self.backend.write_sector(lba, &encoded) {
            return Err(ReplyOutboxCommitError::Indeterminate(
                ReplyOutboxIndeterminate::Storage {
                    operation: ReplyOutboxOperation::Write,
                    slot: Some(slot),
                    error,
                },
            ));
        }
        if let Err(error) = self.backend.flush() {
            return Err(ReplyOutboxCommitError::Indeterminate(
                ReplyOutboxIndeterminate::Storage {
                    operation: ReplyOutboxOperation::Flush,
                    slot: Some(slot),
                    error,
                },
            ));
        }
        let mut readback = [0u8; SECTOR_BYTES];
        if let Err(error) = self.backend.read_sector(lba, &mut readback) {
            return Err(ReplyOutboxCommitError::Indeterminate(
                ReplyOutboxIndeterminate::Storage {
                    operation: ReplyOutboxOperation::Readback,
                    slot: Some(slot),
                    error,
                },
            ));
        }
        if readback != encoded {
            return Err(ReplyOutboxCommitError::Indeterminate(
                ReplyOutboxIndeterminate::PublishReadbackMismatch { slot },
            ));
        }
        match ReplyRecord::decode(&readback) {
            SlotInspection::Valid(receipt)
                if receipt.key == key
                    && receipt.payload_digest == payload_digest
                    && receipt.commit_generation == commit_generation
                    && receipt.self_authenticates() =>
            {
                Ok(receipt)
            }
            SlotInspection::Blank
            | SlotInspection::Valid(_)
            | SlotInspection::TargetCorrupt(_)
            | SlotInspection::UnknownCorrupt => Err(ReplyOutboxCommitError::Indeterminate(
                ReplyOutboxIndeterminate::PublishReadbackMismatch { slot },
            )),
        }
    }

    fn scan(&mut self, reply: ReplyOutboxIdentity) -> ScanResult<B::Error> {
        let mut matching: Option<(u32, ReplyCommitReceipt)> = None;
        let mut first_blank = None;
        let mut max_generation = 0u64;
        let mut ambiguous_corruption = None;
        for slot in 0..OUTBOX_SLOTS {
            let mut sector = [0u8; SECTOR_BYTES];
            if let Err(error) = self.backend.read_sector(slot_lba(slot), &mut sector) {
                return ScanResult::Indeterminate(ReplyOutboxIndeterminate::Storage {
                    operation: ReplyOutboxOperation::Read,
                    slot: Some(slot),
                    error,
                });
            }
            match ReplyRecord::decode(&sector) {
                SlotInspection::Blank => {
                    first_blank.get_or_insert(slot);
                }
                SlotInspection::Valid(receipt) => {
                    max_generation = max_generation.max(receipt.commit_generation);
                    if receipt.reply() == reply {
                        if let Some((first_slot, prior)) = matching {
                            if prior != receipt {
                                return ScanResult::Corrupt(
                                    ReplyOutboxCorruption::ConflictingRecords {
                                        first_slot,
                                        second_slot: slot,
                                    },
                                );
                            }
                        } else {
                            matching = Some((slot, receipt));
                        }
                    }
                }
                SlotInspection::TargetCorrupt(candidate) if candidate == reply => {
                    return ScanResult::Corrupt(ReplyOutboxCorruption::TargetRecord { slot });
                }
                SlotInspection::TargetCorrupt(_) | SlotInspection::UnknownCorrupt => {
                    ambiguous_corruption.get_or_insert(slot);
                }
            }
        }
        // A valid immutable record proves success even if another reply's
        // sector is damaged.  Without a matching record, however, unidentified
        // damage may be the torn target write and absence is unknowable.
        if matching.is_none()
            && let Some(slot) = ambiguous_corruption
        {
            return ScanResult::Indeterminate(ReplyOutboxIndeterminate::AmbiguousCorruption {
                slot,
            });
        }
        ScanResult::Clean(CleanScan {
            matching,
            first_blank,
            max_generation,
        })
    }

    fn scan_delivery(&mut self, reply: ReplyOutboxIdentity) -> DeliveryScanResult<B::Error> {
        let mut apply: Option<(u32, ReplyApplyRecord)> = None;
        let mut acknowledgement: Option<(u32, ReplyAckRecord)> = None;
        let mut first_blank = None;
        let mut max_generation = 0u64;
        let mut ambiguous_corruption = None;
        for slot in 0..DELIVERY_SLOTS {
            let mut sector = [0u8; SECTOR_BYTES];
            if let Err(error) = self
                .backend
                .read_sector(delivery_slot_lba(slot), &mut sector)
            {
                return DeliveryScanResult::Indeterminate(ReplyOutboxIndeterminate::Storage {
                    operation: ReplyOutboxOperation::Read,
                    slot: Some(slot),
                    error,
                });
            }
            match ReplyDeliveryRecord::decode(&sector) {
                DeliverySlotInspection::Blank => {
                    first_blank.get_or_insert(slot);
                }
                DeliverySlotInspection::Valid(record) => {
                    max_generation = max_generation.max(record.generation);
                    if record.key.reply != reply {
                        continue;
                    }
                    match record.kind {
                        ReplyDeliveryKind::Applied => {
                            let observed = ReplyApplyRecord { record };
                            if let Some((first_slot, prior)) = apply {
                                if prior != observed {
                                    return DeliveryScanResult::Corrupt(
                                        ReplyDeliveryCorruption::ConflictingApply {
                                            first_slot,
                                            second_slot: slot,
                                        },
                                    );
                                }
                            } else {
                                apply = Some((slot, observed));
                            }
                        }
                        ReplyDeliveryKind::Acknowledged => {
                            let observed = ReplyAckRecord { record };
                            if let Some((first_slot, prior)) = acknowledgement {
                                if prior != observed {
                                    return DeliveryScanResult::Corrupt(
                                        ReplyDeliveryCorruption::ConflictingAcknowledgement {
                                            first_slot,
                                            second_slot: slot,
                                        },
                                    );
                                }
                            } else {
                                acknowledgement = Some((slot, observed));
                            }
                        }
                    }
                }
                DeliverySlotInspection::TargetCorrupt(candidate) if candidate == reply => {
                    return DeliveryScanResult::Corrupt(ReplyDeliveryCorruption::TargetRecord {
                        slot,
                    });
                }
                DeliverySlotInspection::TargetCorrupt(_)
                | DeliverySlotInspection::UnknownCorrupt => {
                    ambiguous_corruption.get_or_insert(slot);
                }
            }
        }
        if apply.is_none()
            && acknowledgement.is_none()
            && let Some(slot) = ambiguous_corruption
        {
            return DeliveryScanResult::Indeterminate(
                ReplyOutboxIndeterminate::AmbiguousCorruption { slot },
            );
        }
        if let Some((ack_slot, ack)) = acknowledgement {
            let Some((_, applied)) = apply else {
                return DeliveryScanResult::Corrupt(
                    ReplyDeliveryCorruption::AcknowledgementWithoutApply { slot: ack_slot },
                );
            };
            if ack.record.predecessor != applied.record_checksum()
                || ack.record.key != applied.record.key
            {
                return DeliveryScanResult::Corrupt(
                    ReplyDeliveryCorruption::AcknowledgementPredecessorMismatch { slot: ack_slot },
                );
            }
        }
        DeliveryScanResult::Clean(CleanDeliveryScan {
            apply,
            acknowledgement,
            first_blank,
            max_generation,
        })
    }

    #[cfg(ktest)]
    fn into_backend(self) -> B {
        self.backend
    }
}

/// Opening failure before the disk can own an outbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyOutboxOpenError {
    DeviceTooSmall { sectors: u32, required: u32 },
}

/// ATA-backed reply commit provider with a fixed secondary-master attachment.
#[derive(Debug)]
pub(crate) struct AtaPioReplyOutbox {
    outbox: ReplyOutbox<AtaPioDisk>,
}

/// Concrete acquisition failure for the reply outbox fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtaPioReplyOutboxOpenError {
    Ata(AtaPioError),
    Format(ReplyOutboxOpenError),
}

impl AtaPioReplyOutbox {
    /// Exclusively owns the secondary ATA channel and identifies its master.
    /// The primary-master channel remains available to `AtaPioJournal`.
    pub(crate) fn acquire_secondary_master() -> Result<Self, AtaPioReplyOutboxOpenError> {
        let disk = AtaPioDisk::acquire(AtaJournalFixture::SecondaryMaster)
            .map_err(AtaPioReplyOutboxOpenError::Ata)?;
        let outbox = ReplyOutbox::open(disk).map_err(AtaPioReplyOutboxOpenError::Format)?;
        Ok(Self { outbox })
    }

    /// Commits one exact reply record or returns a fail-closed state which must
    /// leave the core obligation and resource claim live.
    pub(crate) fn commit(
        &mut self,
        challenge: &EffectFactChallenge,
        reply_sequence: u64,
        payload_digest: Digest,
    ) -> Result<ReplyCommitReceipt, ReplyOutboxCommitError<AtaPioError>> {
        let key = ReplyCommitKey::from_challenge(challenge, reply_sequence)
            .map_err(ReplyOutboxCommitError::Request)?;
        self.outbox.commit_exact(key, payload_digest)
    }

    /// Re-opens the independent durable source for one reply identity.
    pub(crate) fn inspect(
        &mut self,
        reply: ReplyOutboxIdentity,
    ) -> ReplyCommitInspection<AtaPioError> {
        self.outbox.inspect(reply)
    }

    /// Re-opens the durable apply/ack chain for one stable reply identity.
    pub(crate) fn inspect_delivery(
        &mut self,
        reply: ReplyOutboxIdentity,
    ) -> ReplyDeliveryInspection<AtaPioError> {
        self.outbox.inspect_delivery(reply)
    }

    /// Persists and readback-validates the logical apply publication before
    /// any volatile waiter is woken.
    pub(crate) fn record_apply(
        &mut self,
        plan: ReplyPlan,
        source: ReplyApplySource,
    ) -> Result<ReplyApplyRecord, ReplyDeliveryError<AtaPioError>> {
        self.outbox.record_apply(plan, source)
    }

    /// Persists the exact client acceptance chained to the durable apply
    /// record. Returning success means both flush and readback completed.
    pub(crate) fn record_acknowledgement(
        &mut self,
        plan: ReplyPlan,
        apply: ReplyApplyRecord,
    ) -> Result<ReplyAckRecord, ReplyDeliveryError<AtaPioError>> {
        self.outbox.record_acknowledgement(plan, apply)
    }
}

/// Core verifier for one independently decoded durable apply record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyDurableApplyVerifier {
    plan: ReplyPlan,
}

impl ReplyDurableApplyVerifier {
    pub(crate) const fn new(plan: ReplyPlan) -> Self {
        Self { plan }
    }
}

impl EffectReceiptVerifier for ReplyDurableApplyVerifier {
    type Receipt = ReplyApplyRecord;

    fn identity(&self) -> VerifierIdentity {
        reply_outbox_verifier_identity(
            1,
            REPLY_APPLY_RECEIPT_SCHEMA,
            REPLY_APPLY_IMPLEMENTATION_DIGEST,
        )
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        let coordinate = self.plan.coordinate();
        if challenge.kind() != EffectFactKind::ApplyCompleted
            || challenge.effect() != coordinate.effect()
            || challenge.component() != coordinate.component()
            || challenge.domain() != REPLY_DOMAIN
            || challenge.obligation() != REPLY_OBLIGATION_PUBLICATION
            || challenge.operation() != self.plan.intent_digest()
            || challenge.predecessor().is_some()
            || challenge.expected_verifier() != REPLY_VERIFIER
            || challenge.expected_receipt_schema() != REPLY_APPLY_RECEIPT_SCHEMA
            || !reply_outbox_effect_scope_matches(challenge, REPLY_APPLY_RECEIPT_SCHEMA, 1)
            || !receipt.matches_plan(self.plan)
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedEffectObservation::fact(
            challenge.current_observation(),
            receipt.semantic_digest(),
        ))
    }
}

/// Core verifier for one independently decoded durable client acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyDurableAckVerifier {
    plan: ReplyPlan,
    apply: ReplyApplyRecord,
}

impl ReplyDurableAckVerifier {
    pub(crate) const fn new(plan: ReplyPlan, apply: ReplyApplyRecord) -> Self {
        Self { plan, apply }
    }
}

impl EffectReceiptVerifier for ReplyDurableAckVerifier {
    type Receipt = ReplyAckRecord;

    fn identity(&self) -> VerifierIdentity {
        reply_outbox_verifier_identity(
            1,
            REPLY_SETTLEMENT_RECEIPT_SCHEMA,
            REPLY_SETTLEMENT_IMPLEMENTATION_DIGEST,
        )
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        let coordinate = self.plan.coordinate();
        if challenge.kind() != EffectFactKind::SettlementAcknowledged
            || challenge.effect() != coordinate.effect()
            || challenge.component() != coordinate.component()
            || challenge.domain() != REPLY_DOMAIN
            || challenge.obligation() != REPLY_OBLIGATION_PUBLICATION
            || challenge.operation() != self.plan.intent_digest()
            || challenge.predecessor() != Some(self.apply.semantic_digest())
            || challenge.expected_verifier() != REPLY_VERIFIER
            || challenge.expected_receipt_schema() != REPLY_SETTLEMENT_RECEIPT_SCHEMA
            || !reply_outbox_effect_scope_matches(challenge, REPLY_SETTLEMENT_RECEIPT_SCHEMA, 1)
            || !self.apply.matches_plan(self.plan)
            || !receipt.matches_plan(self.plan, self.apply)
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedEffectObservation::fact(
            challenge.current_observation(),
            receipt.semantic_digest(),
        ))
    }
}

/// Retirement verifier which treats the durable client acceptance as the
/// publication-slot release fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyDurableRetirementVerifier {
    plan: ReplyPlan,
    apply: ReplyApplyRecord,
}

impl ReplyDurableRetirementVerifier {
    pub(crate) const fn new(plan: ReplyPlan, apply: ReplyApplyRecord) -> Self {
        Self { plan, apply }
    }
}

impl ReceiptVerifier for ReplyDurableRetirementVerifier {
    type Receipt = ReplyAckRecord;

    fn identity(&self) -> VerifierIdentity {
        reply_outbox_verifier_identity(1, REPLY_RECEIPT_SCHEMA, REPLY_RECEIPT_IMPLEMENTATION_DIGEST)
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        let coordinate = self.plan.coordinate();
        if challenge.effect() != coordinate.effect()
            || challenge.component() != coordinate.component()
            || challenge.claim() != coordinate.claim()
            || challenge.domain() != REPLY_DOMAIN
            || challenge.kind() != REPLY_EVIDENCE_PUBLICATION_ACK
            || challenge.scope() != ClaimScope::Logical
            || challenge.resource() != coordinate.resource()
            || challenge.resource_generation() != coordinate.resource_generation()
            || !reply_outbox_evidence_scope_matches(challenge, REPLY_RECEIPT_SCHEMA, 1)
            || !self.apply.matches_plan(self.plan)
            || !receipt.matches_plan(self.plan, self.apply)
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new(
            challenge.subject(),
            challenge.current_observation(),
            self.plan.retirement_receipt_digest(),
        ))
    }
}

/// Core verifier for independently read, source-exact outbox records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplyOutboxCommitVerifier {
    epoch: u64,
}

impl ReplyOutboxCommitVerifier {
    pub(crate) const fn new(epoch: u64) -> Option<Self> {
        if epoch == 0 {
            None
        } else {
            Some(Self { epoch })
        }
    }
}

impl EffectReceiptVerifier for ReplyOutboxCommitVerifier {
    type Receipt = ReplyCommitReceipt;

    fn identity(&self) -> VerifierIdentity {
        reply_outbox_verifier_identity(
            self.epoch,
            REPLY_COMMIT_RECEIPT_SCHEMA,
            REPLY_COMMIT_IMPLEMENTATION_DIGEST,
        )
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        if challenge.kind() != EffectFactKind::CommitOutcome
            || challenge.domain() != REPLY_DOMAIN
            || challenge.obligation() != REPLY_OBLIGATION_PUBLICATION
            || challenge.predecessor().is_some()
            || challenge.expected_verifier() != REPLY_VERIFIER
            || challenge.expected_receipt_schema() != REPLY_COMMIT_RECEIPT_SCHEMA
            || !reply_outbox_effect_scope_matches(
                challenge,
                REPLY_COMMIT_RECEIPT_SCHEMA,
                self.epoch,
            )
            || challenge.effect() != receipt.reply().effect()
            || challenge.component() != receipt.component()
            || challenge.actor() != receipt.actor()
            || challenge.generation() != receipt.authority_generation()
            || challenge.nonce() != receipt.intent_nonce()
            || challenge.operation() != receipt.operation()
            || !receipt.self_authenticates()
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedEffectObservation::commit(
            challenge.current_observation(),
            ExternalOutcome::Success,
            receipt.record_checksum(),
        ))
    }
}

/// Exact production identity for a reply outbox verifier.  The generation is
/// deliberately supplied by the outbox verifier so a stale or speculative
/// epoch cannot satisfy a scoped challenge registered for another generation.
fn reply_outbox_verifier_identity(
    generation: u64,
    schema: ReceiptSchemaId,
    implementation_digest: Digest,
) -> VerifierIdentity {
    let generation =
        VerifierGeneration::new(generation).expect("reply outbox verifier generation is non-zero");
    let binding = VerifierBinding::new(REPLY_VERIFIER, generation, schema, implementation_digest)
        .expect("standard reply outbox verifier binding is valid");
    VerifierIdentity::new_exact(binding)
}

fn reply_outbox_binding(generation: u64, schema: ReceiptSchemaId) -> Option<VerifierBinding> {
    let implementation_digest = match schema {
        REPLY_RECEIPT_SCHEMA => REPLY_RECEIPT_IMPLEMENTATION_DIGEST,
        REPLY_COMMIT_RECEIPT_SCHEMA => REPLY_COMMIT_IMPLEMENTATION_DIGEST,
        REPLY_APPLY_RECEIPT_SCHEMA => REPLY_APPLY_IMPLEMENTATION_DIGEST,
        REPLY_SETTLEMENT_RECEIPT_SCHEMA => REPLY_SETTLEMENT_IMPLEMENTATION_DIGEST,
        _ => return None,
    };
    VerifierBinding::new(
        REPLY_VERIFIER,
        VerifierGeneration::new(generation).ok()?,
        schema,
        implementation_digest,
    )
    .ok()
}

fn reply_outbox_effect_scope_matches(
    challenge: &EffectFactChallenge,
    schema: ReceiptSchemaId,
    generation: u64,
) -> bool {
    reply_outbox_scope_matches(
        challenge.verification_scope(),
        challenge.expected_verifier_binding(),
        challenge.effect().operation(),
        schema,
        generation,
    )
}

fn reply_outbox_evidence_scope_matches(
    challenge: &EvidenceChallenge,
    schema: ReceiptSchemaId,
    generation: u64,
) -> bool {
    reply_outbox_scope_matches(
        challenge.verification_scope(),
        challenge.expected_verifier_binding(),
        challenge.effect().operation(),
        schema,
        generation,
    )
}

fn reply_outbox_scope_matches(
    scope: ProviderVerificationScope,
    binding: VerifierBinding,
    operation: cser_core::OperationId,
    schema: ReceiptSchemaId,
    generation: u64,
) -> bool {
    let Some(expected) = reply_outbox_binding(generation, schema) else {
        return false;
    };
    scope.world() == PRODUCTION_WORLD
        && scope.provider() == STANDARD_REPLY_PROVIDER
        && scope.operation() == operation
        && scope.verifier_binding() == binding
        && binding == expected
}

const fn slot_lba(slot: u32) -> u32 {
    FIRST_OUTBOX_LBA + slot
}

const fn delivery_slot_lba(slot: u32) -> u32 {
    FIRST_DELIVERY_LBA + slot
}

fn sector_checksum(mut bytes: [u8; SECTOR_BYTES]) -> Digest {
    bytes[CHECKSUM_OFFSET..CHECKSUM_END].fill(0);
    Digest::new(Sha256::digest(bytes).into())
}

fn delivery_sector_checksum(mut bytes: [u8; SECTOR_BYTES]) -> Digest {
    bytes[DELIVERY_CHECKSUM_OFFSET..DELIVERY_CHECKSUM_END].fill(0);
    Digest::new(Sha256::digest(bytes).into())
}

fn read_array_32(bytes: &[u8], offset: usize) -> [u8; 32] {
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes[offset..offset + 32]);
    result
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(ktest)]
mod tests {
    use alloc::{vec, vec::Vec};

    use cser_core::{
        AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration,
        CatalogSet, ChargeAccountId, ClaimId, ClaimScope, CommandRequest, ComponentCommitOperation,
        ComponentProviderBinding, CoreError, CoreLimits, DEVICE_CLAIM_QUEUE_SLOT,
        DEVICE_COMMIT_RECEIPT_SCHEMA, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DeviceGeneration,
        DeviceScopeId, Digest, Engine, ExecutorCoordinate, ExecutorGeneration, ExecutorId,
        Freshness, JournalGeneration, JournalRecord, OperationId, ProviderCoordinate,
        ProviderGeneration, ProviderId, RegistryInstance, ResourceGeneration, ResourceId,
        TransitionDurability, TransitionOutput, VerifierBinding, VerifierGeneration, WorldId,
        standard_catalog,
    };
    use ostd::prelude::ktest;

    use super::super::core_reply_adapter::{ReplyCoordinate, reply_plan};
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MemoryError {
        Bounds,
        Injected,
    }

    struct MemoryDurability;

    impl TransitionDurability for MemoryDurability {
        type Error = core::convert::Infallible;

        fn persist_transition(
            &mut self,
            record: &JournalRecord,
            _resulting_freshness: Freshness,
            _resulting_projection: Digest,
        ) -> Result<(), Self::Error> {
            assert!(!record.bytes().is_empty());
            Ok(())
        }
    }

    #[derive(Debug)]
    struct MemoryDisk {
        sectors: Vec<[u8; SECTOR_BYTES]>,
        flushes: u32,
        fail_write: bool,
        fail_flush: bool,
        corrupt_readback_lba: Option<u32>,
        last_written_lba: Option<u32>,
    }

    impl MemoryDisk {
        fn fixture() -> Self {
            Self {
                sectors: vec![[0u8; SECTOR_BYTES]; REQUIRED_OUTBOX_SECTORS as usize],
                flushes: 0,
                fail_write: false,
                fail_flush: false,
                corrupt_readback_lba: None,
                last_written_lba: None,
            }
        }
    }

    impl SectorBackend for MemoryDisk {
        type Error = MemoryError;

        fn sector_count(&self) -> u32 {
            self.sectors.len() as u32
        }

        fn read_sector(
            &mut self,
            lba: u32,
            output: &mut [u8; SECTOR_BYTES],
        ) -> Result<(), Self::Error> {
            *output = *self.sectors.get(lba as usize).ok_or(MemoryError::Bounds)?;
            if self.corrupt_readback_lba == Some(lba) && self.last_written_lba == Some(lba) {
                output[111] ^= 0x80;
            }
            Ok(())
        }

        fn write_sector(
            &mut self,
            lba: u32,
            input: &[u8; SECTOR_BYTES],
        ) -> Result<(), Self::Error> {
            if self.fail_write {
                return Err(MemoryError::Injected);
            }
            *self
                .sectors
                .get_mut(lba as usize)
                .ok_or(MemoryError::Bounds)? = *input;
            self.last_written_lba = Some(lba);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            if self.fail_flush {
                return Err(MemoryError::Injected);
            }
            self.flushes += 1;
            Ok(())
        }
    }

    fn digest(marker: u8) -> Digest {
        let mut bytes = [0u8; 32];
        bytes[0] = marker;
        Digest::new(bytes)
    }

    fn key(root: u64, reply_sequence: u64, nonce: u64) -> ReplyCommitKey {
        let operation = OperationId::new(root).unwrap();
        let effect = EffectId::new(operation, 1).unwrap();
        ReplyCommitKey {
            reply: ReplyOutboxIdentity::new(effect, reply_sequence).unwrap(),
            component: AGENT_COMPONENT_REPLY,
            actor: ExecutorCoordinate::new(
                ExecutorId::new(root).unwrap(),
                ExecutorGeneration::new(1).unwrap(),
            ),
            authority_generation: 1,
            intent_nonce: nonce,
            operation: digest(0x41),
        }
    }

    fn delivery_plan(root_value: u64, component: ComponentId) -> ReplyPlan {
        let effect = EffectId::new(OperationId::new(root_value).unwrap(), 1).unwrap();
        let coordinate = ReplyCoordinate::new_component(
            effect,
            component,
            ClaimId::new(root_value).unwrap(),
            ResourceId::new(root_value).unwrap(),
            ResourceGeneration::new(1).unwrap(),
        );
        reply_plan(coordinate, 1, 0xc5e2).unwrap()
    }

    fn commit_challenge(root_value: u64) -> (Engine, cser_core::CommitIntent, EffectFactChallenge) {
        let freshness = Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        );
        let catalog_set = CatalogSet::new(&[standard_catalog()]).unwrap();
        let mut engine = Engine::new(
            WorldId::new(1).unwrap(),
            catalog_set,
            CoreLimits::bounded_default(),
            freshness,
        );
        let mut durability = MemoryDurability;
        let effect = EffectId::new(OperationId::new(root_value).unwrap(), 1).unwrap();
        let actor = ExecutorCoordinate::new(
            ExecutorId::new(root_value).unwrap(),
            ExecutorGeneration::new(1).unwrap(),
        );
        let provider_world = WorldId::new(1).unwrap();
        let provider_reply = ProviderCoordinate::new(
            provider_world,
            ProviderId::new(1).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        let provider_dma = ProviderCoordinate::new(
            provider_world,
            ProviderId::new(2).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        let verifier_generation = VerifierGeneration::new(1).unwrap();
        let verifier_bindings = vec![
            VerifierBinding::new(
                REPLY_VERIFIER,
                verifier_generation,
                REPLY_COMMIT_RECEIPT_SCHEMA,
                REPLY_COMMIT_IMPLEMENTATION_DIGEST,
            )
            .unwrap(),
            VerifierBinding::new(
                REPLY_VERIFIER,
                verifier_generation,
                REPLY_APPLY_RECEIPT_SCHEMA,
                REPLY_APPLY_IMPLEMENTATION_DIGEST,
            )
            .unwrap(),
            VerifierBinding::new(
                REPLY_VERIFIER,
                verifier_generation,
                REPLY_SETTLEMENT_RECEIPT_SCHEMA,
                REPLY_SETTLEMENT_IMPLEMENTATION_DIGEST,
            )
            .unwrap(),
            VerifierBinding::new(
                REPLY_VERIFIER,
                verifier_generation,
                REPLY_RECEIPT_SCHEMA,
                REPLY_RECEIPT_IMPLEMENTATION_DIGEST,
            )
            .unwrap(),
            VerifierBinding::new(
                DEVICE_VERIFIER,
                verifier_generation,
                DEVICE_RECEIPT_SCHEMA,
                Digest::new([0x61; 32]),
            )
            .unwrap(),
            VerifierBinding::new(
                DEVICE_VERIFIER,
                verifier_generation,
                DEVICE_COMMIT_RECEIPT_SCHEMA,
                Digest::new([0x62; 32]),
            )
            .unwrap(),
        ];
        for coordinate in [provider_reply, provider_dma] {
            engine
                .transact(
                    CommandRequest::RegisterProviderGeneration {
                        coordinate,
                        catalog_digest: standard_catalog().digest(),
                        verifier_bindings: verifier_bindings.clone(),
                    },
                    |_| Ok::<(), core::convert::Infallible>(()),
                )
                .unwrap();
        }
        engine
            .transact_durable(
                CommandRequest::AdmitScopedCompositeEffect {
                    effect,
                    origin: actor,
                    kind: AGENT_OPERATION_COMPOSITE,
                    charge_account: ChargeAccountId::new(root_value).unwrap(),
                    bindings: vec![
                        ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, provider_reply),
                        ComponentProviderBinding::new(AGENT_COMPONENT_DMA, provider_dma),
                    ],
                },
                &mut durability,
            )
            .unwrap();
        engine
            .transact_durable(
                CommandRequest::AddComponentClaim {
                    effect,
                    component: AGENT_COMPONENT_REPLY,
                    actor,
                    claim: ClaimId::new(root_value).unwrap(),
                    kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
                    scope: ClaimScope::Logical,
                    resource: ResourceId::new(root_value).unwrap(),
                    resource_generation: ResourceGeneration::new(1).unwrap(),
                    units: 1,
                },
                &mut durability,
            )
            .unwrap();
        engine
            .transact_durable(
                CommandRequest::AddComponentClaim {
                    effect,
                    component: AGENT_COMPONENT_DMA,
                    actor,
                    claim: ClaimId::new(root_value + 1).unwrap(),
                    kind: DEVICE_CLAIM_QUEUE_SLOT,
                    scope: ClaimScope::Device(DeviceScopeId::new(root_value).unwrap()),
                    resource: ResourceId::new(root_value + 1).unwrap(),
                    resource_generation: ResourceGeneration::new(1).unwrap(),
                    units: 3,
                },
                &mut durability,
            )
            .unwrap();
        engine
            .transact_durable(
                CommandRequest::PrepareCompositeEffect { effect, actor },
                &mut durability,
            )
            .unwrap();
        let intent = match engine
            .transact_durable(
                CommandRequest::RecordCompositeCommitIntents {
                    effect,
                    actor,
                    operations: vec![
                        ComponentCommitOperation::new(AGENT_COMPONENT_REPLY, digest(0x61)),
                        ComponentCommitOperation::new(AGENT_COMPONENT_DMA, digest(0x62)),
                    ],
                },
                &mut durability,
            )
            .unwrap()
            .into_output()
        {
            TransitionOutput::CompositeCommitIntents(intents) => intents
                .into_iter()
                .find(|intent| intent.component() == AGENT_COMPONENT_REPLY)
                .expect("atomic arm returns the reply component intent"),
            other => panic!("expected atomic composite commit intents, got {other:?}"),
        };
        let challenge = engine.commit_outcome_challenge(&intent).unwrap();
        (engine, intent, challenge)
    }

    #[ktest]
    fn reply_outbox_commit_flushes_readbacks_and_reopens_source_exact_record() {
        let key = key(41, 7, 3);
        let payload = digest(0x51);
        let mut outbox = ReplyOutbox::open(MemoryDisk::fixture()).expect("open memory outbox");
        assert_eq!(outbox.inspect(key.reply), ReplyCommitInspection::Absent);

        let committed = outbox
            .commit_exact(key, payload)
            .expect("commit exact reply record");
        assert_eq!(committed.reply(), key.reply);
        assert_eq!(committed.payload_digest(), payload);
        assert_eq!(committed.commit_generation(), 1);
        assert!(committed.self_authenticates());

        let disk = outbox.into_backend();
        assert_eq!(disk.flushes, 1);
        let mut reopened = ReplyOutbox::open(disk).expect("reopen same disk image");
        assert_eq!(
            reopened.inspect(key.reply),
            ReplyCommitInspection::Committed(committed)
        );
        assert_eq!(
            reopened
                .commit_exact(key, payload)
                .expect("idempotent exact retry"),
            committed
        );
        assert_eq!(reopened.into_backend().flushes, 1);
    }

    #[ktest]
    fn reply_outbox_distinguishes_absent_corrupt_and_indeterminate() {
        let target = key(42, 8, 4);

        let mut corrupt_disk = MemoryDisk::fixture();
        let mut corrupt = ReplyRecord {
            key: target,
            payload_digest: digest(0x52),
            commit_generation: 1,
        }
        .encode();
        corrupt[CHECKSUM_OFFSET] ^= 1;
        corrupt_disk.sectors[slot_lba(0) as usize] = corrupt;
        let mut corrupt_outbox = ReplyOutbox::open(corrupt_disk).unwrap();
        assert_eq!(
            corrupt_outbox.inspect(target.reply),
            ReplyCommitInspection::Corrupt(ReplyOutboxCorruption::TargetRecord { slot: 0 })
        );

        let mut ambiguous_disk = MemoryDisk::fixture();
        ambiguous_disk.sectors[slot_lba(0) as usize][0] = 0xa5;
        let mut ambiguous_outbox = ReplyOutbox::open(ambiguous_disk).unwrap();
        assert_eq!(
            ambiguous_outbox.inspect(target.reply),
            ReplyCommitInspection::Indeterminate(ReplyOutboxIndeterminate::AmbiguousCorruption {
                slot: 0
            })
        );

        let mut clean_outbox = ReplyOutbox::open(MemoryDisk::fixture()).unwrap();
        assert_eq!(
            clean_outbox.inspect(target.reply),
            ReplyCommitInspection::Absent
        );
    }

    #[ktest]
    fn reply_outbox_never_mints_a_receipt_after_write_or_readback_failure() {
        let target = key(43, 9, 5);
        let mut write_failure = MemoryDisk::fixture();
        write_failure.fail_write = true;
        let mut outbox = ReplyOutbox::open(write_failure).unwrap();
        assert_eq!(
            outbox.commit_exact(target, digest(0x53)),
            Err(ReplyOutboxCommitError::Indeterminate(
                ReplyOutboxIndeterminate::Storage {
                    operation: ReplyOutboxOperation::Write,
                    slot: Some(0),
                    error: MemoryError::Injected,
                }
            ))
        );

        let mut readback_failure = MemoryDisk::fixture();
        readback_failure.corrupt_readback_lba = Some(slot_lba(0));
        let mut outbox = ReplyOutbox::open(readback_failure).unwrap();
        assert_eq!(
            outbox.commit_exact(target, digest(0x53)),
            Err(ReplyOutboxCommitError::Indeterminate(
                ReplyOutboxIndeterminate::PublishReadbackMismatch { slot: 0 }
            ))
        );
    }

    #[ktest]
    fn reply_outbox_identity_is_immutable_and_payload_conflict_backpressures() {
        let target = key(44, 10, 6);
        let mut outbox = ReplyOutbox::open(MemoryDisk::fixture()).unwrap();
        outbox
            .commit_exact(target, digest(0x54))
            .expect("first payload commits");
        assert_eq!(
            outbox.commit_exact(target, digest(0x55)),
            Err(ReplyOutboxCommitError::Corrupt(
                ReplyOutboxCorruption::ConflictingPayload {
                    committed: digest(0x54),
                    requested: digest(0x55),
                }
            ))
        );
    }

    #[ktest]
    fn reply_outbox_verifier_accepts_only_the_independently_decoded_exact_record() {
        let (engine, intent, challenge) = commit_challenge(45);
        let key = ReplyCommitKey::from_challenge(&challenge, 11).unwrap();
        let mut outbox = ReplyOutbox::open(MemoryDisk::fixture()).unwrap();
        let receipt = outbox
            .commit_exact(key, digest(0x62))
            .expect("source record commits and reads back");
        let verifier = ReplyOutboxCommitVerifier::new(1).unwrap();
        assert_eq!(
            verifier.identity().implementation_digest(),
            Some(REPLY_COMMIT_IMPLEMENTATION_DIGEST),
            "the production verifier must expose the registered implementation"
        );

        let _verified = engine
            .verify_commit_outcome(&intent, &verifier, &receipt)
            .expect("exact disk receipt verifies as a known success");

        let wrong_generation = ReplyOutboxCommitVerifier::new(2).unwrap();
        assert_eq!(
            engine.verify_commit_outcome(&intent, &wrong_generation, &receipt),
            Err(CoreError::StaleVerifierEpoch),
            "a verifier generation outside the registered binding fails closed"
        );

        let mut forged = receipt;
        forged.key.intent_nonce = forged.key.intent_nonce.checked_add(1).unwrap();
        assert_eq!(
            engine.verify_commit_outcome(&intent, &verifier, &forged),
            Err(CoreError::VerificationFailed),
            "challenge reflection cannot repair a receipt not decoded from disk"
        );
    }

    #[ktest]
    fn reply_outbox_v3_binds_component_and_older_records_fail_closed() {
        let (engine, intent, challenge) = commit_challenge(46);
        let key = ReplyCommitKey::from_challenge(&challenge, 12).unwrap();
        assert_eq!(key.component, AGENT_COMPONENT_REPLY);
        let payload = digest(0x63);
        let mut outbox = ReplyOutbox::open(MemoryDisk::fixture()).unwrap();
        let exact = outbox.commit_exact(key, payload).unwrap();
        assert_eq!(exact.component(), AGENT_COMPONENT_REPLY);

        let mut disk = outbox.into_backend();
        let slot = slot_lba(0) as usize;
        disk.sectors[slot][144..148].copy_from_slice(&AGENT_COMPONENT_DMA.get().to_le_bytes());
        let checksum = sector_checksum(disk.sectors[slot]);
        disk.sectors[slot][CHECKSUM_OFFSET..CHECKSUM_END].copy_from_slice(&checksum.bytes());
        let mut reopened = ReplyOutbox::open(disk).unwrap();
        let forged = match reopened.inspect(key.reply) {
            ReplyCommitInspection::Committed(receipt) => receipt,
            other => panic!("component-mutated v3 record remained structurally exact: {other:?}"),
        };
        assert_eq!(forged.component(), AGENT_COMPONENT_DMA);
        assert_eq!(
            engine.verify_commit_outcome(
                &intent,
                &ReplyOutboxCommitVerifier::new(1).unwrap(),
                &forged,
            ),
            Err(CoreError::VerificationFailed)
        );
        assert_eq!(
            reopened.commit_exact(key, payload),
            Err(ReplyOutboxCommitError::Corrupt(
                ReplyOutboxCorruption::IdentityMismatch { slot: 0 }
            ))
        );

        let mut v1_disk = MemoryDisk::fixture();
        let mut v1 = ReplyRecord {
            key,
            payload_digest: payload,
            commit_generation: 1,
        }
        .encode();
        v1[8..10].copy_from_slice(&1u16.to_le_bytes());
        let checksum = sector_checksum(v1);
        v1[CHECKSUM_OFFSET..CHECKSUM_END].copy_from_slice(&checksum.bytes());
        v1_disk.sectors[slot] = v1;
        let mut v1_outbox = ReplyOutbox::open(v1_disk).unwrap();
        assert_eq!(
            v1_outbox.inspect(key.reply),
            ReplyCommitInspection::Indeterminate(ReplyOutboxIndeterminate::AmbiguousCorruption {
                slot: 0
            })
        );
    }

    #[ktest]
    fn reply_delivery_flushes_readbacks_reopens_and_is_idempotent() {
        let plan = delivery_plan(47, AGENT_COMPONENT_REPLY);
        let identity = ReplyOutboxIdentity::new(plan.coordinate().effect(), 1).unwrap();
        let source = ReplyApplySource::Committed(digest(0x64));
        let mut outbox = ReplyOutbox::open(MemoryDisk::fixture()).unwrap();
        assert_eq!(
            outbox.inspect_delivery(identity),
            ReplyDeliveryInspection::Absent
        );

        let apply = outbox.record_apply(plan, source).unwrap();
        assert!(apply.matches_plan(plan));
        assert_eq!(apply.source(), source);
        assert!(!apply.semantic_digest().is_zero());
        assert_eq!(outbox.record_apply(plan, source).unwrap(), apply);

        let acknowledgement = outbox.record_acknowledgement(plan, apply).unwrap();
        assert!(acknowledgement.matches_plan(plan, apply));
        assert_eq!(
            acknowledgement.apply_record_checksum(),
            apply.record_checksum()
        );
        assert!(!acknowledgement.record_checksum().is_zero());
        assert_eq!(
            outbox.record_acknowledgement(plan, apply).unwrap(),
            acknowledgement
        );

        let disk = outbox.into_backend();
        assert_eq!(disk.flushes, 2);
        let mut reopened = ReplyOutbox::open(disk).unwrap();
        assert_eq!(
            reopened.inspect_delivery(identity),
            ReplyDeliveryInspection::Acknowledged {
                apply,
                acknowledgement,
            }
        );
        assert_eq!(reopened.record_apply(plan, source).unwrap(), apply);
        assert_eq!(
            reopened.record_acknowledgement(plan, apply).unwrap(),
            acknowledgement
        );
        assert_eq!(reopened.into_backend().flushes, 2);
    }

    #[ktest]
    fn reply_delivery_rejects_ack_without_apply_and_wrong_predecessor() {
        let plan = delivery_plan(48, AGENT_COMPONENT_REPLY);
        let identity = ReplyOutboxIdentity::new(plan.coordinate().effect(), 1).unwrap();
        let apply_record =
            ReplyDeliveryRecord::applied(1, plan, ReplyApplySource::Committed(digest(0x65)))
                .unwrap();
        let apply = ReplyApplyRecord {
            record: apply_record,
        };
        let acknowledgement = ReplyDeliveryRecord::acknowledged(2, plan, apply).unwrap();

        let mut no_apply_disk = MemoryDisk::fixture();
        no_apply_disk.sectors[delivery_slot_lba(0) as usize] = acknowledgement.encode();
        let mut no_apply = ReplyOutbox::open(no_apply_disk).unwrap();
        assert_eq!(
            no_apply.inspect_delivery(identity),
            ReplyDeliveryInspection::Corrupt(
                ReplyDeliveryCorruption::AcknowledgementWithoutApply { slot: 0 }
            )
        );

        let mut wrong_predecessor = acknowledgement;
        wrong_predecessor.predecessor = digest(0x66);
        wrong_predecessor.record_checksum = Digest::ZERO;
        wrong_predecessor.record_checksum = delivery_sector_checksum(wrong_predecessor.encode());
        let mut mismatch_disk = MemoryDisk::fixture();
        mismatch_disk.sectors[delivery_slot_lba(0) as usize] = apply_record.encode();
        mismatch_disk.sectors[delivery_slot_lba(1) as usize] = wrong_predecessor.encode();
        let mut mismatch = ReplyOutbox::open(mismatch_disk).unwrap();
        assert_eq!(
            mismatch.inspect_delivery(identity),
            ReplyDeliveryInspection::Corrupt(
                ReplyDeliveryCorruption::AcknowledgementPredecessorMismatch { slot: 1 }
            )
        );
    }

    #[ktest]
    fn reply_delivery_never_mints_records_after_write_flush_or_readback_failure() {
        let plan = delivery_plan(49, AGENT_COMPONENT_REPLY);
        let source = ReplyApplySource::AtomicArmIndeterminate(digest(0x67));

        let mut write_failure = MemoryDisk::fixture();
        write_failure.fail_write = true;
        let mut outbox = ReplyOutbox::open(write_failure).unwrap();
        assert_eq!(
            outbox.record_apply(plan, source),
            Err(ReplyDeliveryError::Indeterminate(
                ReplyOutboxIndeterminate::Storage {
                    operation: ReplyOutboxOperation::Write,
                    slot: Some(0),
                    error: MemoryError::Injected,
                }
            ))
        );

        let mut flush_failure = MemoryDisk::fixture();
        flush_failure.fail_flush = true;
        let mut outbox = ReplyOutbox::open(flush_failure).unwrap();
        assert_eq!(
            outbox.record_apply(plan, source),
            Err(ReplyDeliveryError::Indeterminate(
                ReplyOutboxIndeterminate::Storage {
                    operation: ReplyOutboxOperation::Flush,
                    slot: Some(0),
                    error: MemoryError::Injected,
                }
            ))
        );

        let mut readback_failure = MemoryDisk::fixture();
        readback_failure.corrupt_readback_lba = Some(delivery_slot_lba(0));
        let mut outbox = ReplyOutbox::open(readback_failure).unwrap();
        assert_eq!(
            outbox.record_apply(plan, source),
            Err(ReplyDeliveryError::Indeterminate(
                ReplyOutboxIndeterminate::PublishReadbackMismatch { slot: 0 }
            ))
        );

        let mut outbox = ReplyOutbox::open(MemoryDisk::fixture()).unwrap();
        let apply = outbox.record_apply(plan, source).unwrap();
        let mut ack_failure_disk = outbox.into_backend();
        ack_failure_disk.fail_flush = true;
        let mut outbox = ReplyOutbox::open(ack_failure_disk).unwrap();
        assert_eq!(
            outbox.record_acknowledgement(plan, apply),
            Err(ReplyDeliveryError::Indeterminate(
                ReplyOutboxIndeterminate::Storage {
                    operation: ReplyOutboxOperation::Flush,
                    slot: Some(1),
                    error: MemoryError::Injected,
                }
            ))
        );
    }

    #[ktest]
    fn reply_delivery_rejects_forged_component_plan() {
        let plan = delivery_plan(50, AGENT_COMPONENT_REPLY);
        let forged = delivery_plan(50, AGENT_COMPONENT_DMA);
        let source = ReplyApplySource::Committed(digest(0x68));
        let mut outbox = ReplyOutbox::open(MemoryDisk::fixture()).unwrap();
        let apply = outbox.record_apply(plan, source).unwrap();
        assert!(!apply.matches_plan(forged));
        assert_eq!(
            outbox.record_apply(forged, source),
            Err(ReplyDeliveryError::PlanConflict)
        );
        assert_eq!(
            outbox.record_acknowledgement(forged, apply),
            Err(ReplyDeliveryError::PlanConflict)
        );
    }
}
