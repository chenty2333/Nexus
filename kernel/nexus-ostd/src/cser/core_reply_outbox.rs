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
//! indeterminate so the causal estate continues to own its reply obligation
//! and publication slot.
//!
//! Evidence boundary: the QEMU raw-image fixture and an acknowledged emulated
//! ATA flush demonstrate the source-exact kernel/PIO/device-model path across
//! emulator restarts.  They are not evidence for physical-media power-loss
//! atomicity, controller write-cache behavior, host-filesystem durability, or
//! physical cold-boot recovery.

use cser_core::{
    Digest, EffectFactChallenge, EffectFactKind, EffectId, EffectReceiptVerifier, ExternalOutcome,
    PrincipalIncarnation, REPLY_COMMIT_RECEIPT_SCHEMA, REPLY_DOMAIN, REPLY_OBLIGATION_PUBLICATION,
    REPLY_VERIFIER, VerificationError, VerifiedEffectObservation, VerifierIdentity,
};
use sha2::{Digest as _, Sha256};

use super::core_pio_journal::{
    AtaJournalFixture, AtaPioDisk, AtaPioError, SECTOR_BYTES, SectorBackend,
};

// LBA 0 remains untouched.  The bounded append-only shape turns capacity and
// ambiguous media damage into explicit backpressure rather than overwriting a
// possibly committed reply.
const FIRST_OUTBOX_LBA: u32 = 1;
const OUTBOX_SLOTS: u32 = 128;
const REQUIRED_OUTBOX_SECTORS: u32 = FIRST_OUTBOX_LBA + OUTBOX_SLOTS;

const RECORD_MAGIC: [u8; 8] = *b"CSEROUT\0";
const RECORD_VERSION: u16 = 1;
const RECORD_LEN: u16 = 208;
const RECORD_STATE_COMMITTED: u32 = 1;

const CHECKSUM_OFFSET: usize = 176;
const CHECKSUM_END: usize = 208;

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
    actor: PrincipalIncarnation,
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

    pub(crate) const fn actor(self) -> PrincipalIncarnation {
        self.key.actor
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
        bytes[24..32].copy_from_slice(&self.key.reply.effect().root().get().to_le_bytes());
        bytes[32..40].copy_from_slice(&self.key.reply.effect().sequence().to_le_bytes());
        bytes[40..48].copy_from_slice(&self.key.reply.sequence().to_le_bytes());
        bytes[48..56].copy_from_slice(&self.key.actor.principal().get().to_le_bytes());
        bytes[56..64].copy_from_slice(&self.key.actor.generation().to_le_bytes());
        bytes[64..72].copy_from_slice(&self.key.authority_generation.to_le_bytes());
        bytes[72..80].copy_from_slice(&self.key.intent_nonce.to_le_bytes());
        bytes[80..112].copy_from_slice(&self.key.operation.bytes());
        bytes[112..144].copy_from_slice(&self.payload_digest.bytes());
        // 144..176 is reserved and must remain zero.  The digest covers the
        // exact framing plus every reserved and trailing byte.
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
            || bytes[144..CHECKSUM_OFFSET].iter().any(|byte| *byte != 0)
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

fn decode_structural_key(bytes: &[u8; SECTOR_BYTES]) -> Option<ReplyCommitKey> {
    if bytes[..8] != RECORD_MAGIC
        || read_u16(bytes, 8) != RECORD_VERSION
        || read_u16(bytes, 10) != RECORD_LEN
        || read_u32(bytes, 12) != RECORD_STATE_COMMITTED
    {
        return None;
    }
    let root = cser_core::RootId::new(read_u64(bytes, 24)).ok()?;
    let effect = EffectId::new(root, read_u64(bytes, 32)).ok()?;
    let reply = ReplyOutboxIdentity::new(effect, read_u64(bytes, 40))?;
    let principal = cser_core::PrincipalId::new(read_u64(bytes, 48)).ok()?;
    let actor = PrincipalIncarnation::new(principal, read_u64(bytes, 56)).ok()?;
    let authority_generation = read_u64(bytes, 64);
    let intent_nonce = read_u64(bytes, 72);
    let operation = Digest::new(read_array_32(bytes, 80));
    if authority_generation == 0 || intent_nonce == 0 || operation.is_zero() {
        return None;
    }
    Some(ReplyCommitKey {
        reply,
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

enum ScanResult<E> {
    Clean(CleanScan),
    Corrupt(ReplyOutboxCorruption),
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
        VerifierIdentity::new(REPLY_VERIFIER, self.epoch, REPLY_COMMIT_RECEIPT_SCHEMA)
            .expect("non-zero outbox verifier epoch is valid")
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
            || challenge.effect() != receipt.reply().effect()
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

const fn slot_lba(slot: u32) -> u32 {
    FIRST_OUTBOX_LBA + slot
}

fn sector_checksum(mut bytes: [u8; SECTOR_BYTES]) -> Digest {
    bytes[CHECKSUM_OFFSET..CHECKSUM_END].fill(0);
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
        BootGeneration, ChargeAccountId, ClaimId, ClaimScope, CommandRequest, CoreError,
        CoreLimits, DeviceGeneration, Engine, Freshness, JournalGeneration, JournalRecord,
        PrincipalId, RegistryInstance, ResourceGeneration, ResourceId, RootId,
        TransitionDurability, TransitionOutput, standard_catalog,
    };
    use ostd::prelude::ktest;

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
        corrupt_readback_lba: Option<u32>,
        last_written_lba: Option<u32>,
    }

    impl MemoryDisk {
        fn fixture() -> Self {
            Self {
                sectors: vec![[0u8; SECTOR_BYTES]; REQUIRED_OUTBOX_SECTORS as usize],
                flushes: 0,
                fail_write: false,
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
        let effect = EffectId::new(RootId::new(root).unwrap(), 1).unwrap();
        ReplyCommitKey {
            reply: ReplyOutboxIdentity::new(effect, reply_sequence).unwrap(),
            actor: PrincipalIncarnation::new(PrincipalId::new(root).unwrap(), 1).unwrap(),
            authority_generation: 1,
            intent_nonce: nonce,
            operation: digest(0x41),
        }
    }

    fn commit_challenge(root_value: u64) -> (Engine, cser_core::CommitIntent, EffectFactChallenge) {
        let freshness = Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            1,
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        )
        .unwrap();
        let mut engine = Engine::new(standard_catalog(), CoreLimits::bounded_default(), freshness);
        let mut durability = MemoryDurability;
        let effect = EffectId::new(RootId::new(root_value).unwrap(), 1).unwrap();
        let actor = PrincipalIncarnation::new(PrincipalId::new(root_value).unwrap(), 1).unwrap();
        engine
            .transact_durable(
                CommandRequest::CreateEstate {
                    effect,
                    origin: actor,
                    binding_generation: 1,
                    domain: REPLY_DOMAIN,
                    obligation: REPLY_OBLIGATION_PUBLICATION,
                    charge_account: ChargeAccountId::new(root_value).unwrap(),
                },
                &mut durability,
            )
            .unwrap();
        engine
            .transact_durable(
                CommandRequest::AddClaim {
                    effect,
                    actor,
                    binding_generation: 1,
                    claim: ClaimId::new(root_value).unwrap(),
                    domain: REPLY_DOMAIN,
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
                CommandRequest::PrepareEffect {
                    effect,
                    actor,
                    binding_generation: 1,
                },
                &mut durability,
            )
            .unwrap();
        let intent = match engine
            .transact_durable(
                CommandRequest::RecordCommitIntent {
                    effect,
                    actor,
                    binding_generation: 1,
                    operation: digest(0x61),
                },
                &mut durability,
            )
            .unwrap()
            .into_output()
        {
            TransitionOutput::CommitIntent(intent) => intent,
            other => panic!("expected commit intent, got {other:?}"),
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

        let _verified = engine
            .verify_commit_outcome(&intent, &verifier, &receipt)
            .expect("exact disk receipt verifies as a known success");

        let mut forged = receipt;
        forged.key.intent_nonce = forged.key.intent_nonce.checked_add(1).unwrap();
        assert_eq!(
            engine.verify_commit_outcome(&intent, &verifier, &forged),
            Err(CoreError::VerificationFailed),
            "challenge reflection cannot repair a receipt not decoded from disk"
        );
    }
}
