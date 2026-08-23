// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec::Vec};

use sha2::{Digest as _, Sha256};

use crate::{
    BootGeneration, CSER_CORE_API_PROFILE_VERSION, DeviceGeneration, Digest, JournalGeneration,
    RecoveryBinding, RecoveryProfile, RegistryInstance, WorldId,
    engine::{CommandDecodeError, CommandKind, MAX_COMMAND_PAYLOAD_BYTES},
};

pub(crate) use crate::recovery_source;
use crate::recovery_source::{
    JournalRecoverySource, ReadAtCursor, ReadAtError, RecoveryExpectation,
};

/// Magic prefix of every CSER journal record.
pub const JOURNAL_MAGIC: [u8; 8] = *b"CSERJ12\0";
/// Frozen journal schema for the current CSER Core semantic API profile.
pub const JOURNAL_SCHEMA_VERSION: u16 = 12;
/// Semantic core API profile explicitly bound in every schema-11 envelope.
pub const JOURNAL_CORE_API_PROFILE: u16 = CSER_CORE_API_PROFILE_VERSION;

/// Magic prefix of a portable exact-replay checkpoint envelope.
///
/// This is deliberately distinct from a journal record. A checkpoint carries
/// a canonical *image* of the exact journal prefix it replaces; it is not a
/// lossy serialization of the private engine state.
pub const JOURNAL_CHECKPOINT_MAGIC: [u8; 8] = *b"CSERCP5\0";
/// Version of [`JournalCheckpoint`] envelopes.
pub const JOURNAL_CHECKPOINT_VERSION: u16 = 5;
const PREVIOUS_CHECKPOINT_MAGIC: [u8; 8] = *b"CSERCP4\0";
const LEGACY_CHECKPOINT_MAGIC: [u8; 8] = *b"CSERCP1\0";

const PRE_HANDOFF_RESOLUTION_JOURNAL_MAGIC: [u8; 8] = *b"CSERJR7\0";
const PRE_HANDOFF_RESOLUTION_JOURNAL_SCHEMA_VERSION: u16 = 7;
const PREVIOUS_JOURNAL_MAGIC: [u8; 8] = *b"CSERJ11\0";
const PREVIOUS_JOURNAL_SCHEMA_VERSION: u16 = 11;
const PREVIOUS_PREVIOUS_JOURNAL_MAGIC: [u8; 8] = *b"CSERJR9\0";
const PREVIOUS_PREVIOUS_JOURNAL_SCHEMA_VERSION: u16 = 9;
const PROFILE_ONE_JOURNAL_MAGIC: [u8; 8] = *b"CSERJR5\0";
const PROFILE_ONE_JOURNAL_SCHEMA_VERSION: u16 = 5;
const LEGACY_JOURNAL_MAGIC: [u8; 8] = *b"CSERJR4\0";
const LEGACY_JOURNAL_SCHEMA_VERSION: u16 = 4;

// prefix + revisions + profile + world + catalog + registry +
// freshness axes + base projection + predecessor + payload length.
/// Fixed prefix length of the current journal record, excluding its digest.
///
/// The streaming checkpoint plan uses this exact envelope width instead of a
/// second checkpoint-specific wire grammar.
pub(crate) const JOURNAL_RECORD_FIXED_WITHOUT_DIGEST: usize = 180;
/// Width of the current record digest.
pub(crate) const JOURNAL_RECORD_DIGEST_LEN: usize = 32;
const FIXED_WITHOUT_DIGEST: usize = JOURNAL_RECORD_FIXED_WITHOUT_DIGEST;
const DIGEST_LEN: usize = JOURNAL_RECORD_DIGEST_LEN;
const MIN_RECORD_LEN: usize = FIXED_WITHOUT_DIGEST + DIGEST_LEN;
#[cfg(feature = "std")]
pub(crate) const JOURNAL_RECORD_HEADER_LEN: usize = 16;
pub(crate) const MAX_JOURNAL_RECORD_BYTES: usize =
    FIXED_WITHOUT_DIGEST + MAX_COMMAND_PAYLOAD_BYTES + DIGEST_LEN;
const CHECKPOINT_FIXED_WITHOUT_DIGEST: usize =
    8 + 2 + 2 + 4 + 8 + 8 + 32 + 8 + 8 + 32 + 32 + 32 + 4;
const CHECKPOINT_MIN_LEN: usize = CHECKPOINT_FIXED_WITHOUT_DIGEST + DIGEST_LEN;
/// Largest exact journal image accepted by the portable checkpoint envelope.
///
/// This is deliberately a conservative bounded recovery input, not a claim
/// that a checkpoint compacts journal history.
pub const MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES: usize = 16 * 1024 * 1024;

/// Portable byte ceiling for one in-memory journal scan.
///
/// This is four times the bounded checkpoint image budget, allowing a small
/// amount of ordinary replay history while keeping malformed recovery input
/// from forcing unbounded record materialization. Host backends must compact
/// or rotate before exceeding this admission limit.
pub(crate) const MAX_JOURNAL_SCAN_BYTES: usize = 64 * 1024 * 1024;

/// Portable record-count ceiling for one in-memory journal scan.
///
/// The count bound complements [`MAX_JOURNAL_SCAN_BYTES`] for minimal records,
/// limiting the `JournalScan` record vector to 65,536 entries.
pub(crate) const MAX_JOURNAL_SCAN_RECORDS: usize = 65_536;

/// Exact trusted coordinates bound by a [`JournalCheckpoint`].
///
/// A storage implementation may atomically anchor this tuple (and the
/// envelope digest) before replacing an older journal prefix. In particular,
/// the projection is not advisory telemetry: restore recomputes it before the
/// checkpoint can be accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalCheckpointAnchor {
    binding: RecoveryBinding,
    catalog_digest: Digest,
    freshness: crate::Freshness,
    revision: u64,
    head: Digest,
    projection: Digest,
    envelope: Digest,
}

impl JournalCheckpointAnchor {
    /// Returns the complete immutable recovery binding.
    pub const fn binding(self) -> RecoveryBinding {
        self.binding
    }
    /// Returns the aggregate catalog-set digest protecting the replay image.
    pub const fn catalog_digest(self) -> Digest {
        self.catalog_digest
    }
    /// Returns the exact recovered freshness coordinates.
    pub const fn freshness(self) -> crate::Freshness {
        self.freshness
    }
    /// Returns the covered journal revision.
    pub const fn revision(self) -> u64 {
        self.revision
    }
    /// Returns the covered journal head.
    pub const fn head(self) -> Digest {
        self.head
    }
    /// Returns the deterministic projection digest which must be rebuilt.
    pub const fn projection(self) -> Digest {
        self.projection
    }
    /// Returns the digest of the complete encoded envelope.
    pub const fn envelope(self) -> Digest {
        self.envelope
    }
}

/// Canonical, self-checking exact-replay image for journal replacement.
///
/// The envelope is intentionally not a compact state snapshot. It contains
/// the original command records verbatim, so decoding rebuilds the state by
/// normal command replay, invariant checks, and projection recomputation.
/// This makes it safe for a journal backend to replace one validated prefix,
/// but does not by itself reduce journal space; a future compact checkpoint
/// needs a separately specified canonical state codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalCheckpoint {
    binding: RecoveryBinding,
    catalog_digest: Digest,
    freshness: crate::Freshness,
    revision: u64,
    head: Digest,
    projection: Digest,
    image: Arc<[u8]>,
    envelope: Digest,
}

impl JournalCheckpoint {
    /// Returns the complete immutable binding encoded in this checkpoint.
    pub const fn binding(&self) -> RecoveryBinding {
        self.binding
    }

    pub(crate) fn build(
        binding: RecoveryBinding,
        freshness: crate::Freshness,
        revision: u64,
        head: Digest,
        projection: Digest,
        image: &[u8],
    ) -> Result<Self, JournalCheckpointDecodeError> {
        if (revision == 0) != head.is_zero()
            || projection.is_zero()
            || freshness.registry() != binding.registry()
        {
            return Err(JournalCheckpointDecodeError::InvalidCoordinates);
        }
        if image.len() > MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES {
            return Err(JournalCheckpointDecodeError::ImageTooLarge);
        }
        let image_len =
            u32::try_from(image.len()).map_err(|_| JournalCheckpointDecodeError::LengthOverflow)?;
        let total = CHECKPOINT_FIXED_WITHOUT_DIGEST
            .checked_add(image.len())
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(JournalCheckpointDecodeError::LengthOverflow)?;
        let total_u32 =
            u32::try_from(total).map_err(|_| JournalCheckpointDecodeError::LengthOverflow)?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&JOURNAL_CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&JOURNAL_CHECKPOINT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&JOURNAL_CORE_API_PROFILE.to_le_bytes());
        bytes.extend_from_slice(&total_u32.to_le_bytes());
        put_profile(&mut bytes, binding.profile());
        bytes.extend_from_slice(&binding.world().get().to_le_bytes());
        bytes.extend_from_slice(&binding.catalog_digest().bytes());
        bytes.extend_from_slice(&binding.registry().get().to_le_bytes());
        bytes.extend_from_slice(&revision.to_le_bytes());
        bytes.extend_from_slice(&head.bytes());
        bytes.extend_from_slice(&projection.bytes());
        put_freshness(&mut bytes, freshness);
        bytes.extend_from_slice(&image_len.to_le_bytes());
        bytes.extend_from_slice(image);
        let envelope = Digest::new(Sha256::digest(&bytes).into());
        Ok(Self {
            binding,
            catalog_digest: binding.catalog_digest(),
            freshness,
            revision,
            head,
            projection,
            image: Arc::from(image.to_vec().into_boxed_slice()),
            envelope,
        })
    }

    /// Decodes a structurally valid checkpoint envelope.
    ///
    /// Call [`Self::recover`] with a trusted advancing anchor before trusting the contained projection or
    /// replacing a journal: structural decoding does not interpret commands.
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalCheckpointDecodeError> {
        if bytes.len() >= PREVIOUS_CHECKPOINT_MAGIC.len() && bytes[..8] == PREVIOUS_CHECKPOINT_MAGIC
        {
            return Err(JournalCheckpointDecodeError::UnsupportedVersion { version: 4 });
        }
        if bytes.len() >= LEGACY_CHECKPOINT_MAGIC.len() && bytes[..8] == LEGACY_CHECKPOINT_MAGIC {
            return Err(JournalCheckpointDecodeError::UnsupportedVersion { version: 1 });
        }
        if bytes.len() < CHECKPOINT_MIN_LEN {
            return Err(JournalCheckpointDecodeError::InvalidLength);
        }
        if bytes[..8] != JOURNAL_CHECKPOINT_MAGIC {
            return Err(JournalCheckpointDecodeError::BadMagic);
        }
        let version = checkpoint_read_u16(bytes, 8)?;
        if version != JOURNAL_CHECKPOINT_VERSION {
            return Err(JournalCheckpointDecodeError::UnsupportedVersion { version });
        }
        let envelope_profile = checkpoint_read_u16(bytes, 10)?;
        if envelope_profile != JOURNAL_CORE_API_PROFILE {
            return Err(JournalCheckpointDecodeError::UnsupportedApiProfile {
                profile: envelope_profile,
            });
        }
        let total = usize::try_from(checkpoint_read_u32(bytes, 12)?)
            .map_err(|_| JournalCheckpointDecodeError::InvalidLength)?;
        if total != bytes.len() || total < CHECKPOINT_MIN_LEN {
            return Err(JournalCheckpointDecodeError::InvalidLength);
        }
        let digest_offset = total
            .checked_sub(DIGEST_LEN)
            .ok_or(JournalCheckpointDecodeError::InvalidLength)?;
        // Reject oversized or structurally inconsistent images before hashing
        // attacker-controlled input. This is the recovery-input admission
        // bound, not merely an allocation bound.
        let image_len = usize::try_from(checkpoint_read_u32(bytes, 176)?)
            .map_err(|_| JournalCheckpointDecodeError::InvalidLength)?;
        if image_len > MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES {
            return Err(JournalCheckpointDecodeError::ImageTooLarge);
        }
        let image_end = 180usize
            .checked_add(image_len)
            .ok_or(JournalCheckpointDecodeError::InvalidLength)?;
        if image_end != digest_offset {
            return Err(JournalCheckpointDecodeError::InvalidLength);
        }
        let expected = Digest::new(
            bytes[digest_offset..]
                .try_into()
                .map_err(|_| JournalCheckpointDecodeError::InvalidLength)?,
        );
        let actual = Digest::new(Sha256::digest(&bytes[..digest_offset]).into());
        if expected != actual {
            return Err(JournalCheckpointDecodeError::ChecksumMismatch);
        }
        let profile = read_profile(bytes, 16)?;
        let world = WorldId::new(read_u64(bytes, 24))
            .map_err(|_| JournalCheckpointDecodeError::ZeroIdentity)?;
        let catalog_digest = Digest::new(
            bytes[32..64]
                .try_into()
                .map_err(|_| JournalCheckpointDecodeError::InvalidLength)?,
        );
        let registry = RegistryInstance::new(checkpoint_read_u64(bytes, 64)?)
            .map_err(|_| JournalCheckpointDecodeError::ZeroIdentity)?;
        let revision = checkpoint_read_u64(bytes, 72)?;
        let head = Digest::new(
            bytes[80..112]
                .try_into()
                .map_err(|_| JournalCheckpointDecodeError::InvalidLength)?,
        );
        let projection = Digest::new(
            bytes[112..144]
                .try_into()
                .map_err(|_| JournalCheckpointDecodeError::InvalidLength)?,
        );
        let freshness = checkpoint_read_freshness(bytes, 144)?;
        let binding = RecoveryBinding::new(profile, world, catalog_digest, registry)
            .map_err(|_| JournalCheckpointDecodeError::InvalidCoordinates)?;
        if profile != RecoveryProfile::current() {
            return Err(JournalCheckpointDecodeError::UnsupportedApiProfile {
                profile: profile.core_api(),
            });
        }
        if (revision == 0) != head.is_zero()
            || projection.is_zero()
            || freshness.registry() != binding.registry()
        {
            return Err(JournalCheckpointDecodeError::InvalidCoordinates);
        }
        Ok(Self {
            binding,
            catalog_digest,
            freshness,
            revision,
            head,
            projection,
            image: Arc::from(bytes[180..image_end].to_vec().into_boxed_slice()),
            envelope: expected,
        })
    }

    /// Recovers the checkpoint image through the normal trusted-anchor path.
    ///
    /// The anchor is consumed by the engine's validated recovery path, which
    /// reserves a newer freshness epoch, fences operations, and quarantines
    /// device claims.
    /// This API deliberately cannot return an old-epoch writable engine.
    pub fn recover(
        &self,
        catalog: crate::CatalogSet,
        limits: crate::CoreLimits,
        anchor: crate::RecoveryAnchor,
    ) -> Result<crate::RecoveryReport, crate::CoreError> {
        let expected = self.anchor();
        if anchor.binding() != expected.binding()
            || anchor.catalog_digest() != expected.catalog_digest()
            || anchor.committed_freshness() != expected.freshness()
            || anchor.minimum_revision() != expected.revision()
            || anchor.expected_head() != expected.head()
            || anchor.projection() != expected.projection()
        {
            return Err(crate::CoreError::RollbackDetected);
        }
        // Replay and validate the image once, then install the transient
        // recovery overlay on that validated engine without replaying it a
        // second time.
        crate::Engine::recover_validated_journal_checkpoint(catalog, limits, self, anchor)
    }

    /// Returns the trusted coordinates which must be anchored with this image.
    pub const fn anchor(&self) -> JournalCheckpointAnchor {
        JournalCheckpointAnchor {
            binding: self.binding,
            catalog_digest: self.catalog_digest,
            freshness: self.freshness,
            revision: self.revision,
            head: self.head,
            projection: self.projection,
            envelope: self.envelope,
        }
    }
    /// Returns the verbatim exact journal image.
    pub fn image(&self) -> &[u8] {
        &self.image
    }
    /// Encodes this checkpoint envelope without retaining a duplicate buffer.
    pub fn encode(&self) -> Vec<u8> {
        let image_len = u32::try_from(self.image.len()).expect("checkpoint image was bounded");
        let total = CHECKPOINT_FIXED_WITHOUT_DIGEST + self.image.len() + DIGEST_LEN;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&JOURNAL_CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&JOURNAL_CHECKPOINT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&JOURNAL_CORE_API_PROFILE.to_le_bytes());
        bytes.extend_from_slice(
            &(u32::try_from(total).expect("checkpoint envelope was bounded")).to_le_bytes(),
        );
        put_profile(&mut bytes, self.binding.profile());
        bytes.extend_from_slice(&self.binding.world().get().to_le_bytes());
        bytes.extend_from_slice(&self.binding.catalog_digest().bytes());
        bytes.extend_from_slice(&self.binding.registry().get().to_le_bytes());
        bytes.extend_from_slice(&self.revision.to_le_bytes());
        bytes.extend_from_slice(&self.head.bytes());
        bytes.extend_from_slice(&self.projection.bytes());
        put_freshness(&mut bytes, self.freshness);
        bytes.extend_from_slice(&image_len.to_le_bytes());
        bytes.extend_from_slice(&self.image);
        debug_assert_eq!(Digest::new(Sha256::digest(&bytes).into()), self.envelope);
        bytes.extend_from_slice(&self.envelope.bytes());
        bytes
    }
}

/// Failure while decoding a [`JournalCheckpoint`] envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalCheckpointDecodeError {
    /// The envelope is too short or has inconsistent declared lengths.
    InvalidLength,
    /// The envelope prefix is not the checkpoint magic.
    BadMagic,
    /// The envelope version is unsupported.
    UnsupportedVersion {
        /// Unsupported envelope version.
        version: u16,
    },
    /// The checkpoint binds an unsupported semantic profile.
    UnsupportedApiProfile {
        /// Unsupported semantic API profile.
        profile: u16,
    },
    /// A length cannot be represented by the envelope.
    LengthOverflow,
    /// Catalog, revision, or head coordinates are structurally inconsistent.
    InvalidCoordinates,
    /// The trailing envelope digest does not match its contents.
    ChecksumMismatch,
    /// A non-zero freshness identity decoded as zero.
    ZeroIdentity,
    /// The image exceeds [`MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES`].
    ImageTooLarge,
}

fn put_freshness(bytes: &mut Vec<u8>, freshness: crate::Freshness) {
    bytes.extend_from_slice(&freshness.boot().get().to_le_bytes());
    bytes.extend_from_slice(&freshness.registry().get().to_le_bytes());
    bytes.extend_from_slice(&freshness.device().get().to_le_bytes());
    bytes.extend_from_slice(&freshness.journal().get().to_le_bytes());
}

fn put_profile(bytes: &mut Vec<u8>, profile: RecoveryProfile) {
    bytes.extend_from_slice(&profile.core_api().to_le_bytes());
    bytes.extend_from_slice(&profile.journal_schema().to_le_bytes());
    bytes.extend_from_slice(&profile.projection_schema().to_le_bytes());
    bytes.extend_from_slice(&profile.checkpoint_schema().to_le_bytes());
}

fn read_profile(
    bytes: &[u8],
    offset: usize,
) -> Result<RecoveryProfile, JournalCheckpointDecodeError> {
    RecoveryProfile::new(
        checkpoint_read_u16(bytes, offset)?,
        checkpoint_read_u16(bytes, offset + 2)?,
        checkpoint_read_u16(bytes, offset + 4)?,
        checkpoint_read_u16(bytes, offset + 6)?,
    )
    .map_err(|_| JournalCheckpointDecodeError::InvalidCoordinates)
}

fn checkpoint_read_u16(bytes: &[u8], offset: usize) -> Result<u16, JournalCheckpointDecodeError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(JournalCheckpointDecodeError::InvalidLength)?
            .try_into()
            .map_err(|_| JournalCheckpointDecodeError::InvalidLength)?,
    ))
}
fn checkpoint_read_u32(bytes: &[u8], offset: usize) -> Result<u32, JournalCheckpointDecodeError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(JournalCheckpointDecodeError::InvalidLength)?
            .try_into()
            .map_err(|_| JournalCheckpointDecodeError::InvalidLength)?,
    ))
}
fn checkpoint_read_u64(bytes: &[u8], offset: usize) -> Result<u64, JournalCheckpointDecodeError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(JournalCheckpointDecodeError::InvalidLength)?
            .try_into()
            .map_err(|_| JournalCheckpointDecodeError::InvalidLength)?,
    ))
}
fn checkpoint_read_freshness(
    bytes: &[u8],
    offset: usize,
) -> Result<crate::Freshness, JournalCheckpointDecodeError> {
    let boot = crate::BootGeneration::new(checkpoint_read_u64(bytes, offset)?)
        .map_err(|_| JournalCheckpointDecodeError::ZeroIdentity)?;
    let registry = crate::RegistryInstance::new(checkpoint_read_u64(bytes, offset + 8)?)
        .map_err(|_| JournalCheckpointDecodeError::ZeroIdentity)?;
    let device = crate::DeviceGeneration::new(checkpoint_read_u64(bytes, offset + 16)?)
        .map_err(|_| JournalCheckpointDecodeError::ZeroIdentity)?;
    let journal = crate::JournalGeneration::new(checkpoint_read_u64(bytes, offset + 24)?)
        .map_err(|_| JournalCheckpointDecodeError::ZeroIdentity)?;
    Ok(crate::Freshness::new(boot, registry, device, journal))
}

/// One validated, hash-chained CSER journal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRecord {
    base_revision: u64,
    revision: u64,
    boot: BootGeneration,
    registry: RegistryInstance,
    journal: JournalGeneration,
    device: DeviceGeneration,
    profile: RecoveryProfile,
    world: WorldId,
    catalog_digest: Digest,
    base_projection: Digest,
    predecessor: Digest,
    command: CommandKind,
    digest: Digest,
    bytes: Arc<[u8]>,
}

impl JournalRecord {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build(
        base_revision: u64,
        freshness: crate::Freshness,
        binding: RecoveryBinding,
        base_projection: Digest,
        predecessor: Digest,
        command: CommandKind,
    ) -> Result<Self, JournalDecodeError> {
        let revision = base_revision
            .checked_add(1)
            .ok_or(JournalDecodeError::RevisionOverflow)?;
        if base_projection.is_zero() || freshness.registry() != binding.registry() {
            return Err(JournalDecodeError::InvalidBinding);
        }
        let payload_len = command
            .try_encoded_payload_len()
            .map_err(JournalDecodeError::Command)?;
        let total_len = MIN_RECORD_LEN
            .checked_add(payload_len)
            .ok_or(JournalDecodeError::LengthOverflow)?;
        let total_len_u32 =
            u32::try_from(total_len).map_err(|_| JournalDecodeError::LengthOverflow)?;
        let payload_len_u32 =
            u32::try_from(payload_len).map_err(|_| JournalDecodeError::LengthOverflow)?;

        let mut bytes = Vec::with_capacity(total_len);
        bytes.extend_from_slice(&JOURNAL_MAGIC);
        bytes.extend_from_slice(&JOURNAL_SCHEMA_VERSION.to_le_bytes());
        bytes.extend_from_slice(&JOURNAL_CORE_API_PROFILE.to_le_bytes());
        bytes.extend_from_slice(&total_len_u32.to_le_bytes());
        bytes.extend_from_slice(&base_revision.to_le_bytes());
        bytes.extend_from_slice(&revision.to_le_bytes());
        put_profile(&mut bytes, binding.profile());
        bytes.extend_from_slice(&binding.world().get().to_le_bytes());
        bytes.extend_from_slice(&binding.catalog_digest().bytes());
        bytes.extend_from_slice(&binding.registry().get().to_le_bytes());
        bytes.extend_from_slice(&freshness.boot().get().to_le_bytes());
        bytes.extend_from_slice(&freshness.journal().get().to_le_bytes());
        bytes.extend_from_slice(&freshness.device().get().to_le_bytes());
        bytes.extend_from_slice(&base_projection.bytes());
        bytes.extend_from_slice(&predecessor.bytes());
        bytes.extend_from_slice(&payload_len_u32.to_le_bytes());
        command
            .encode_payload_into(&mut bytes)
            .map_err(JournalDecodeError::Command)?;
        if bytes.len() != total_len - DIGEST_LEN {
            return Err(JournalDecodeError::PayloadLengthMismatch {
                expected: total_len - DIGEST_LEN,
                actual: bytes.len(),
            });
        }
        debug_assert_eq!(bytes.len(), total_len - DIGEST_LEN);

        let digest = Digest::new(Sha256::digest(&bytes).into());
        bytes.extend_from_slice(&digest.bytes());

        Ok(Self {
            base_revision,
            revision,
            boot: freshness.boot(),
            registry: freshness.registry(),
            journal: freshness.journal(),
            device: freshness.device(),
            profile: binding.profile(),
            world: binding.world(),
            catalog_digest: binding.catalog_digest(),
            base_projection,
            predecessor,
            command,
            digest,
            bytes: Arc::from(bytes.into_boxed_slice()),
        })
    }

    /// Returns the revision this record expects before replay.
    pub const fn base_revision(&self) -> u64 {
        self.base_revision
    }

    /// Returns the revision after this record.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the boot generation recorded at preparation.
    pub const fn boot(&self) -> BootGeneration {
        self.boot
    }

    /// Returns the Registry instance.
    pub const fn registry(&self) -> RegistryInstance {
        self.registry
    }

    /// Returns the journal generation.
    pub const fn journal(&self) -> JournalGeneration {
        self.journal
    }

    /// Returns the device generation.
    pub const fn device(&self) -> DeviceGeneration {
        self.device
    }

    /// Returns the aggregate catalog-set digest bound by this record.
    pub const fn catalog_digest(&self) -> Digest {
        self.catalog_digest
    }

    /// Returns the immutable schema tuple.
    pub const fn profile(&self) -> RecoveryProfile {
        self.profile
    }

    /// Returns the semantic world bound by this record.
    pub const fn world(&self) -> WorldId {
        self.world
    }

    /// Returns the complete immutable binding encoded by this record.
    pub fn recovery_binding(&self) -> RecoveryBinding {
        RecoveryBinding::new(self.profile, self.world, self.catalog_digest, self.registry)
            .expect("journal record stores validated binding")
    }

    /// Returns the projection digest immediately before this transition.
    pub const fn base_projection(&self) -> Digest {
        self.base_projection
    }

    /// Returns the predecessor record digest.
    pub const fn predecessor(&self) -> Digest {
        self.predecessor
    }

    pub(crate) const fn command(&self) -> &CommandKind {
        &self.command
    }

    /// Returns whether this record is the internal whole-state checkpoint
    /// representation eligible for physical journal replacement.
    pub(crate) const fn is_whole_state_checkpoint(&self) -> bool {
        matches!(self.command, CommandKind::WholeStateCheckpointV1 { .. })
    }

    /// Returns this record's digest.
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// Returns the exact durable bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[cfg(test)]
    pub(crate) fn shares_bytes_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.bytes, &other.bytes)
    }

    #[cfg(test)]
    pub(crate) fn shares_checkpoint_image_with(&self, other: &Self) -> bool {
        match (&self.command, &other.command) {
            (
                CommandKind::WholeStateCheckpointV1 { state: left, .. },
                CommandKind::WholeStateCheckpointV1 { state: right, .. },
            ) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    /// Returns a test-only record whose encoded revision is changed while its
    /// envelope checksum is recomputed. Production constructors cannot mint
    /// this malformed relation; the helper exercises downstream guards that
    /// must still fail closed if a hostile adapter supplies one.
    #[cfg(test)]
    pub(crate) fn with_revision_for_test(&self, revision: u64) -> Self {
        let mut record = self.clone();
        let mut bytes = self.bytes.to_vec();
        bytes[24..32].copy_from_slice(&revision.to_le_bytes());
        let digest = Digest::new(Sha256::digest(&bytes[..bytes.len() - DIGEST_LEN]).into());
        let digest_offset = bytes.len() - DIGEST_LEN;
        bytes[digest_offset..].copy_from_slice(&digest.bytes());
        record.revision = revision;
        record.digest = digest;
        record.bytes = Arc::from(bytes.into_boxed_slice());
        record
    }
}

/// Failure while decoding a durable journal stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalDecodeError {
    /// A complete record did not begin with the CSER magic.
    BadMagic {
        /// Byte offset of the bad record.
        offset: usize,
    },
    /// The schema version is unsupported.
    UnsupportedVersion {
        /// Unsupported version.
        version: u16,
    },
    /// The record binds a core API profile this decoder cannot execute.
    UnsupportedApiProfile {
        /// Unsupported semantic API profile.
        profile: u16,
    },
    /// A declared record length is structurally invalid.
    InvalidLength,
    /// The complete scan input exceeds the portable byte budget.
    InputTooLarge {
        /// Maximum accepted scan input in bytes.
        limit: usize,
    },
    /// The complete scan contains more records than the portable budget.
    RecordCountExceeded {
        /// Maximum accepted record count.
        limit: usize,
    },
    /// A length cannot be represented by the journal format.
    LengthOverflow,
    /// A revision increment overflowed.
    RevisionOverflow,
    /// A non-zero stable identity decoded as zero.
    ZeroIdentity,
    /// The immutable record binding disagrees with its freshness coordinates.
    InvalidBinding,
    /// The payload does not encode a known command.
    Command(CommandDecodeError),
    /// The canonical payload length calculation disagrees with encoding.
    PayloadLengthMismatch {
        /// Number of bytes reserved by the canonical length calculation.
        expected: usize,
        /// Number of bytes actually written by the encoder.
        actual: usize,
    },
    /// The trailing digest does not match the record bytes.
    ChecksumMismatch {
        /// Byte offset of the corrupt record.
        offset: usize,
    },
    /// A record does not continue the immediately preceding journal chain.
    ChainMismatch {
        /// Byte offset of the record which breaks the chain.
        offset: usize,
    },
}

/// Storage repair required before appending after anchored recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalRepair {
    /// An incomplete final record follows the accepted head.
    TornTail {
        /// First byte not belonging to the accepted prefix.
        offset: usize,
    },
    /// Bytes not committed by the trusted freshness anchor follow its head.
    UnanchoredSuffix {
        /// First byte not belonging to the accepted prefix.
        offset: usize,
    },
}

impl JournalRepair {
    /// Returns the exact accepted-prefix length and truncation boundary.
    pub const fn offset(self) -> usize {
        match self {
            Self::TornTail { offset } | Self::UnanchoredSuffix { offset } => offset,
        }
    }
}

/// Result of scanning a byte stream for complete records and a torn tail.
#[derive(Clone, Debug)]
pub struct JournalScan {
    records: Vec<JournalRecord>,
    torn_tail: Option<usize>,
    unanchored_suffix: Option<usize>,
}

impl JournalScan {
    /// Returns all complete, checksum-valid records.
    pub fn records(&self) -> &[JournalRecord] {
        &self.records
    }

    /// Consumes the scan and returns complete records.
    pub fn into_records(self) -> Vec<JournalRecord> {
        self.records
    }

    /// Returns the byte offset of an incomplete final record.
    pub const fn torn_tail(&self) -> Option<usize> {
        self.torn_tail
    }

    /// Returns the first byte after an explicitly selected trusted head.
    ///
    /// This is populated only by [`scan_journal_to_head`] when additional
    /// bytes follow the selected record. Those bytes are not interpreted as
    /// authoritative journal state.
    pub const fn unanchored_suffix(&self) -> Option<usize> {
        self.unanchored_suffix
    }
}

/// The fixed, decoded metadata of one borrowed journal record.
///
/// The metadata is copied from the fixed J10 envelope, but the record and
/// payload bytes remain borrowed from the scan input.  This is the part of a
/// [`JournalRecord`] needed by recovery before a normal command is decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JournalRecordMeta {
    base_revision: u64,
    revision: u64,
    freshness: crate::Freshness,
    binding: RecoveryBinding,
    base_projection: Digest,
    predecessor: Digest,
}

impl JournalRecordMeta {
    /// Returns the revision expected before this record.
    pub(crate) const fn base_revision(self) -> u64 {
        self.base_revision
    }

    /// Returns the revision after this record.
    pub(crate) const fn revision(self) -> u64 {
        self.revision
    }

    /// Returns the complete freshness vector encoded by this record.
    pub(crate) const fn freshness(self) -> crate::Freshness {
        self.freshness
    }

    /// Returns the aggregate catalog digest encoded by this record.
    pub(crate) const fn catalog_digest(self) -> Digest {
        self.binding.catalog_digest()
    }

    /// Returns the complete recovery binding encoded by this record.
    pub(crate) const fn recovery_binding(self) -> RecoveryBinding {
        self.binding
    }

    /// Returns the projection digest immediately before this transition.
    pub(crate) const fn base_projection(self) -> Digest {
        self.base_projection
    }

    /// Returns the predecessor record digest.
    pub(crate) const fn predecessor(self) -> Digest {
        self.predecessor
    }
}

/// Borrowed projection of the internal whole-state checkpoint command.
///
/// All slices and ranges refer directly to the input passed to the anchored
/// scan.  In particular, obtaining this view does not create the `Arc<[u8]>`
/// owned by [`CommandKind::WholeStateCheckpointV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WholeStateCheckpointView<'a> {
    input: &'a [u8],
    projection: Digest,
    state_start: usize,
    state_len: usize,
}

impl<'a> WholeStateCheckpointView<'a> {
    /// Returns the canonical projection digest carried by the checkpoint.
    pub(crate) const fn projection(self) -> Digest {
        self.projection
    }

    /// Returns the absolute input range containing the checkpoint state.
    pub(crate) fn state_range(self) -> core::ops::Range<usize> {
        self.state_start..self.state_start + self.state_len
    }

    /// Returns the checkpoint state without copying it.
    pub(crate) fn state(self) -> &'a [u8] {
        &self.input[self.state_range()]
    }
}

/// One J10 record validated in place against a borrowed journal input.
///
/// The view owns no record bytes and does not allocate command state. Recovery
/// decodes ordinary command payloads on demand and consumes
/// [`Self::whole_state_checkpoint`] directly for the large checkpoint payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JournalRecordView<'a> {
    input: &'a [u8],
    offset: usize,
    total_len: usize,
    payload_len: usize,
    meta: JournalRecordMeta,
    digest: Digest,
    checkpoint_projection: Option<Digest>,
    checkpoint_state_start: usize,
    checkpoint_state_len: usize,
}

impl<'a> JournalRecordView<'a> {
    /// Returns the fixed metadata decoded from this record's envelope.
    pub(crate) const fn meta(self) -> JournalRecordMeta {
        self.meta
    }

    /// Returns the absolute input range containing this record's command
    /// payload, excluding the fixed envelope and trailing digest.
    pub(crate) const fn payload_range(self) -> core::ops::Range<usize> {
        let start = self.offset + FIXED_WITHOUT_DIGEST;
        start..start + self.payload_len
    }

    /// Returns this record's command payload without copying it.
    pub(crate) fn payload(self) -> &'a [u8] {
        &self.input[self.payload_range()]
    }

    /// Returns this record's validated digest.
    pub(crate) const fn digest(self) -> Digest {
        self.digest
    }

    /// Returns the checkpoint projection and borrowed state, if this is a
    /// `WholeStateCheckpointV1` record.
    pub(crate) fn whole_state_checkpoint(self) -> Option<WholeStateCheckpointView<'a>> {
        self.checkpoint_projection
            .map(|projection| WholeStateCheckpointView {
                input: self.input,
                projection,
                state_start: self.checkpoint_state_start,
                state_len: self.checkpoint_state_len,
            })
    }
}

/// Result of an anchored borrowed scan.
///
/// Complete records in the accepted prefix are represented by views into the
/// caller's input.  As with [`JournalScan`], a torn tail is only reported when
/// it follows a successfully selected head; bytes after that head are never
/// interpreted and are reported as an unanchored suffix.
#[derive(Clone, Debug)]
pub(crate) struct JournalScanView<'a> {
    records: Vec<JournalRecordView<'a>>,
    torn_tail: Option<usize>,
    unanchored_suffix: Option<usize>,
}

impl<'a> JournalScanView<'a> {
    /// Returns all validated views in the accepted prefix.
    pub(crate) fn records(&self) -> &[JournalRecordView<'a>] {
        &self.records
    }

    /// Returns the byte offset of a torn tail after the selected head.
    pub(crate) const fn torn_tail(&self) -> Option<usize> {
        self.torn_tail
    }

    /// Returns the first byte after the selected trusted head.
    pub(crate) const fn unanchored_suffix(&self) -> Option<usize> {
        self.unanchored_suffix
    }
}

/// Absolute location of the leading whole-state checkpoint, when present.
///
/// This contains only fixed metadata. The checkpoint state remains in the
/// recovery source and is never retained by the scanner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadAtCheckpointLocation {
    record_offset: usize,
    record_len: usize,
    state_offset: usize,
    state_len: usize,
    projection: Digest,
}

impl ReadAtCheckpointLocation {
    #[cfg(test)]
    pub(crate) const fn record_offset(self) -> usize {
        self.record_offset
    }

    #[cfg(test)]
    pub(crate) const fn record_len(self) -> usize {
        self.record_len
    }

    pub(crate) const fn state_offset(self) -> usize {
        self.state_offset
    }

    pub(crate) const fn state_len(self) -> usize {
        self.state_len
    }

    pub(crate) const fn projection(self) -> Digest {
        self.projection
    }
}

/// Constant-sized layout of the journal prefix accepted by an exact anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadAtJournalLayout {
    accepted_len: usize,
    record_count: usize,
    leading_checkpoint: Option<ReadAtCheckpointLocation>,
}

impl ReadAtJournalLayout {
    pub(crate) const fn accepted_len(self) -> usize {
        self.accepted_len
    }

    pub(crate) const fn record_count(self) -> usize {
        self.record_count
    }

    #[cfg(test)]
    pub(crate) const fn leading_checkpoint(self) -> Option<ReadAtCheckpointLocation> {
        self.leading_checkpoint
    }
}

/// Fixed metadata for one record in an already anchored positioned prefix.
///
/// The scanner has authenticated the record before this view is returned.
/// Replaying a source only rereads the bounded envelope and, for ordinary
/// commands, one bounded payload; it never materializes the complete record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadAtRecordLocation {
    offset: usize,
    total_len: usize,
    payload_offset: usize,
    payload_len: usize,
    meta: JournalRecordMeta,
    digest: Digest,
    checkpoint: Option<ReadAtCheckpointLocation>,
}

impl ReadAtRecordLocation {
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }

    pub(crate) const fn total_len(self) -> usize {
        self.total_len
    }

    pub(crate) const fn payload_offset(self) -> usize {
        self.payload_offset
    }

    pub(crate) const fn payload_len(self) -> usize {
        self.payload_len
    }

    pub(crate) const fn meta(self) -> JournalRecordMeta {
        self.meta
    }

    pub(crate) const fn digest(self) -> Digest {
        self.digest
    }

    pub(crate) const fn checkpoint(self) -> Option<ReadAtCheckpointLocation> {
        self.checkpoint
    }
}

/// Non-authorizing result of inspecting one physical recovery candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AnchoredJournalInspection {
    layout: ReadAtJournalLayout,
    accepted_prefix_digest: Digest,
    repair: Option<JournalRepair>,
}

impl AnchoredJournalInspection {
    pub(crate) const fn layout(self) -> ReadAtJournalLayout {
        self.layout
    }

    #[cfg(test)]
    pub(crate) const fn accepted_prefix_digest(self) -> Digest {
        self.accepted_prefix_digest
    }

    pub(crate) const fn repair(self) -> Option<JournalRepair> {
        self.repair
    }
}

/// Failure while inspecting a positioned recovery source.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum AnchoredJournalInspectionError<E> {
    /// The caller supplied no I/O scratch.
    EmptyScratch,
    /// The provider rejected a read or reported that its snapshot changed.
    Source(E),
    /// The J10 envelope or accepted chain was malformed.
    Journal(JournalDecodeError),
}

/// Scans a journal byte stream.
///
/// Only an incomplete final record is classified as a torn tail. A malformed
/// or checksum-invalid complete record fails closed. The complete input is
/// admitted only within [`MAX_JOURNAL_SCAN_BYTES`] and
/// [`MAX_JOURNAL_SCAN_RECORDS`].
pub fn scan_journal(bytes: &[u8]) -> Result<JournalScan, JournalDecodeError> {
    if bytes.len() > MAX_JOURNAL_SCAN_BYTES {
        return Err(JournalDecodeError::InputTooLarge {
            limit: MAX_JOURNAL_SCAN_BYTES,
        });
    }
    let (scan, _) = scan_journal_inner(bytes, None)?;
    validate_owned_chain(scan.records())?;
    Ok(scan)
}

/// Validates records only through one exact externally anchored head.
///
/// Bytes after the selected record are deliberately not decoded. They may be
/// a complete append whose freshness anchor never committed, a torn append, or
/// arbitrary failed-write residue. The returned suffix offset must be repaired
/// before the recovered engine can accept another transition. The byte and
/// record limits apply only to the validated prefix, so an oversized suffix
/// does not prevent finding an early trusted head.
///
/// Returns `None` when the exact head does not occur in the validated prefix.
pub fn scan_journal_to_head(
    bytes: &[u8],
    expected_head: Digest,
) -> Result<Option<JournalScan>, JournalDecodeError> {
    let (scan, found) = scan_journal_inner(bytes, Some(expected_head))?;
    Ok(found.then_some(scan))
}

/// Scans through one externally anchored head without materializing records.
///
/// Every complete record through `expected_head` is checked against the J10
/// header grammar, bounded length, command payload grammar, SHA-256 digest,
/// and the contiguous revision/predecessor chain.  A whole-state checkpoint
/// payload is recognized and exposed as borrowed slices; it is not converted
/// into a `CommandKind` or an owned `Arc<[u8]>`.  Ordinary command payloads
/// are decoded only for validation and can be decoded again on demand by the
/// recovery replay helper.
///
/// The scanner stops immediately after the exact expected head.  Any bytes
/// following it are reported as [`JournalScanView::unanchored_suffix`] and are
/// not interpreted, including a complete or corrupt record and an oversized
/// suffix.  If the head is absent, including when a torn or corrupt record is
/// encountered before it, the function returns `Ok(None)` so recovery cannot
/// accept a partial or differently anchored prefix.
pub(crate) fn scan_journal_to_head_borrowed(
    bytes: &[u8],
    expected_head: Digest,
) -> Result<Option<JournalScanView<'_>>, JournalDecodeError> {
    let (scan, found) = scan_journal_views_inner(bytes, Some(expected_head), true)?;
    Ok(found.then_some(scan))
}

/// Scans a complete journal byte stream without materializing records.
///
/// The returned metadata and command views borrow directly from `bytes`, so a
/// whole-state checkpoint does not allocate either its command image or a
/// second owned copy of its record.  This is the host-adapter equivalent of
/// [`scan_journal`]; the owned scanner remains available to callers that need
/// replayable [`JournalRecord`] values.
#[cfg(any(feature = "std", test))]
pub(crate) fn scan_journal_borrowed(
    bytes: &[u8],
) -> Result<JournalScanView<'_>, JournalDecodeError> {
    if bytes.len() > MAX_JOURNAL_SCAN_BYTES {
        return Err(JournalDecodeError::InputTooLarge {
            limit: MAX_JOURNAL_SCAN_BYTES,
        });
    }
    let (scan, found) = scan_journal_views_inner(bytes, None, true)?;
    debug_assert!(!found);
    Ok(scan)
}

/// Inspects one stable positioned source through an exact trusted J10 head.
///
/// The result is deliberately non-authorizing: it is sufficient to compare
/// physical candidates, but engine recovery must rescan the selected source
/// while consuming a trusted recovery anchor. This first slice validates the
/// complete J10 envelope, checksum, binding, freshness endpoint, and hash
/// chain without retaining record bytes. Whole-state checkpoint framing is
/// also validated and returned as offsets. Allocation-free semantic preflight
/// of ordinary command payloads belongs to the engine integration slice; this
/// function therefore must not be used as its substitute. The one deliberate
/// freshness exception is a terminal `CheckpointRecovery` record: its
/// pre-transition envelope freshness is accepted only when the command target
/// itself matches the trusted post-transition anchor.
#[cfg(test)]
pub(crate) fn inspect_journal_source_to_head<S: JournalRecoverySource>(
    expectation: RecoveryExpectation,
    source: &mut S,
    scratch: &mut [u8],
) -> Result<Option<AnchoredJournalInspection>, AnchoredJournalInspectionError<S::Error>> {
    if scratch.is_empty() {
        return Err(AnchoredJournalInspectionError::EmptyScratch);
    }
    let snapshot = source
        .begin_snapshot()
        .map_err(AnchoredJournalInspectionError::Source)?;
    let inspected = inspect_journal_snapshot_to_head(expectation, source, snapshot, scratch);
    if inspected.is_ok() {
        source
            .validate_snapshot(snapshot.token())
            .map_err(AnchoredJournalInspectionError::Source)?;
    }
    inspected
}

/// Inspects an already-open stable snapshot without ending its lifetime.
///
/// Engine recovery uses this form so J10 validation, checkpoint decoding, and
/// suffix replay all remain covered by one final `validate_snapshot` call.
pub(crate) fn inspect_journal_snapshot_to_head<S: JournalRecoverySource>(
    expectation: RecoveryExpectation,
    source: &mut S,
    snapshot: recovery_source::RecoverySourceSnapshot<S::Snapshot>,
    scratch: &mut [u8],
) -> Result<Option<AnchoredJournalInspection>, AnchoredJournalInspectionError<S::Error>> {
    if scratch.is_empty() {
        return Err(AnchoredJournalInspectionError::EmptyScratch);
    }
    // The logical length may include an arbitrarily large unanchored suffix.
    // Only bytes through the trusted head are admitted to the scan budget;
    // the suffix is intentionally neither read nor hashed.
    let source_len = snapshot.logical_len();

    if expectation.revision() == 0 || expectation.head().is_zero() {
        if expectation.revision() != 0 || !expectation.head().is_zero() {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::ChainMismatch { offset: 0 },
            ));
        }
        return Ok(Some(AnchoredJournalInspection {
            layout: ReadAtJournalLayout {
                accepted_len: 0,
                record_count: 0,
                leading_checkpoint: None,
            },
            accepted_prefix_digest: Digest::new(Sha256::digest([]).into()),
            repair: (source_len != 0).then_some(JournalRepair::UnanchoredSuffix { offset: 0 }),
        }));
    }

    let mut offset = 0usize;
    let mut record_count = 0usize;
    let mut previous: Option<(u64, Digest)> = None;
    let mut leading_checkpoint = None;
    let mut prefix_hasher = Sha256::new();

    while (offset as u64) < source_len {
        if record_count >= MAX_JOURNAL_SCAN_RECORDS {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::RecordCountExceeded {
                    limit: MAX_JOURNAL_SCAN_RECORDS,
                },
            ));
        }
        let remaining = source_len.saturating_sub(offset as u64);
        if remaining < 16 {
            return Ok(None);
        }

        let mut header = [0u8; 16];
        read_source_exact(source, snapshot, offset, &mut header, scratch)?;
        reject_read_at_record_magic_prefix(&header, offset)?;
        let version = read_u16(&header, 8);
        if version != JOURNAL_SCHEMA_VERSION {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::UnsupportedVersion { version },
            ));
        }
        let envelope_profile = read_u16(&header, 10);
        if envelope_profile != JOURNAL_CORE_API_PROFILE {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::UnsupportedApiProfile {
                    profile: envelope_profile,
                },
            ));
        }
        let total_len = read_u32(&header, 12) as usize;
        if !(MIN_RECORD_LEN..=MAX_JOURNAL_RECORD_BYTES).contains(&total_len) {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::InvalidLength,
            ));
        }
        if u64::try_from(total_len)
            .ok()
            .is_none_or(|length| length > remaining)
        {
            return Ok(None);
        }
        if offset > MAX_JOURNAL_SCAN_BYTES.saturating_sub(total_len) {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::InputTooLarge {
                    limit: MAX_JOURNAL_SCAN_BYTES,
                },
            ));
        }
        let mut fixed = [0u8; FIXED_WITHOUT_DIGEST];
        read_source_exact(source, snapshot, offset, &mut fixed, scratch)?;
        let payload_len = read_u32(&fixed, 176) as usize;
        if payload_len > MAX_COMMAND_PAYLOAD_BYTES {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::Command(CommandDecodeError::PayloadTooLarge),
            ));
        }
        if FIXED_WITHOUT_DIGEST
            .checked_add(payload_len)
            .and_then(|value| value.checked_add(DIGEST_LEN))
            != Some(total_len)
        {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::InvalidLength,
            ));
        }
        if payload_len == 0 {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::Command(CommandDecodeError::UnexpectedEof),
            ));
        }

        let digest_offset = offset.checked_add(total_len - DIGEST_LEN).ok_or_else(|| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::LengthOverflow)
        })?;
        let mut record_hasher = Sha256::new();
        let mut hash_cursor = ReadAtCursor::new(
            source,
            snapshot.token(),
            snapshot.logical_len(),
            offset as u64,
            (total_len - DIGEST_LEN) as u64,
            scratch,
        )
        .map_err(map_read_at_inspection_error)?;
        hash_cursor
            .stream_bytes((total_len - DIGEST_LEN) as u64, |chunk| {
                record_hasher.update(chunk);
                prefix_hasher.update(chunk);
            })
            .map_err(map_read_at_inspection_error)?;
        let actual = Digest::new(record_hasher.finalize().into());
        let mut expected_bytes = [0u8; DIGEST_LEN];
        read_source_exact(
            source,
            snapshot,
            digest_offset,
            &mut expected_bytes,
            scratch,
        )?;
        let expected = Digest::new(expected_bytes);
        if expected != actual {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::ChecksumMismatch { offset },
            ));
        }
        prefix_hasher.update(expected_bytes);

        let profile = read_profile(&fixed, 32).map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::InvalidLength)
        })?;
        if profile != RecoveryProfile::current() {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::UnsupportedApiProfile {
                    profile: profile.core_api(),
                },
            ));
        }
        let world = WorldId::new(read_u64(&fixed, 40)).map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::ZeroIdentity)
        })?;
        let catalog_digest = Digest::new(fixed[48..80].try_into().map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::InvalidLength)
        })?);
        let registry = RegistryInstance::new(read_u64(&fixed, 80)).map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::ZeroIdentity)
        })?;
        let boot = BootGeneration::new(read_u64(&fixed, 88)).map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::ZeroIdentity)
        })?;
        let journal = JournalGeneration::new(read_u64(&fixed, 96)).map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::ZeroIdentity)
        })?;
        let device = DeviceGeneration::new(read_u64(&fixed, 104)).map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::ZeroIdentity)
        })?;
        let base_projection = Digest::new(fixed[112..144].try_into().map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::InvalidLength)
        })?);
        if base_projection.is_zero() {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::InvalidBinding,
            ));
        }
        let binding =
            RecoveryBinding::new(profile, world, catalog_digest, registry).map_err(|_| {
                AnchoredJournalInspectionError::Journal(JournalDecodeError::InvalidBinding)
            })?;
        if binding != expectation.binding() {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::InvalidBinding,
            ));
        }
        let predecessor = Digest::new(fixed[144..176].try_into().map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::InvalidLength)
        })?);
        let meta = JournalRecordMeta {
            base_revision: read_u64(&fixed, 16),
            revision: read_u64(&fixed, 24),
            freshness: crate::Freshness::new(boot, registry, device, journal),
            binding,
            base_projection,
            predecessor,
        };

        let mut tag = [0u8; 1];
        read_source_exact(
            source,
            snapshot,
            offset + FIXED_WITHOUT_DIGEST,
            &mut tag,
            scratch,
        )?;
        let checkpoint = tag[0] == 37;
        if let Some((revision, head)) = previous {
            validate_record_successor(
                meta.base_revision,
                meta.revision,
                meta.predecessor,
                revision,
                head,
                offset,
            )
            .map_err(AnchoredJournalInspectionError::Journal)?;
        } else {
            validate_record_start(
                meta.base_revision,
                meta.revision,
                meta.predecessor,
                checkpoint,
                offset,
            )
            .map_err(AnchoredJournalInspectionError::Journal)?;
        }
        if checkpoint {
            let location = inspect_read_at_checkpoint_payload(
                source,
                snapshot,
                offset,
                total_len,
                payload_len,
                scratch,
            )?;
            if record_count == 0 {
                leading_checkpoint = Some(location);
            }
        }

        offset = offset.checked_add(total_len).ok_or_else(|| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::LengthOverflow)
        })?;
        record_count += 1;
        previous = Some((meta.revision, expected));
        if expected == expectation.head() {
            let freshness_matches = if meta.freshness == expectation.freshness() {
                true
            } else if !checkpoint && tag[0] == 17 && payload_len == 25 {
                let mut recovery_payload = [0u8; 25];
                read_source_exact(
                    source,
                    snapshot,
                    offset - total_len + FIXED_WITHOUT_DIGEST,
                    &mut recovery_payload,
                    scratch,
                )?;
                read_u64(&recovery_payload, 1) == expectation.freshness().boot().get()
                    && read_u64(&recovery_payload, 9) == expectation.freshness().journal().get()
                    && read_u64(&recovery_payload, 17) == expectation.freshness().device().get()
            } else {
                false
            };
            if meta.revision != expectation.revision() || !freshness_matches {
                return Err(AnchoredJournalInspectionError::Journal(
                    JournalDecodeError::ChainMismatch {
                        offset: offset - total_len,
                    },
                ));
            }
            return Ok(Some(AnchoredJournalInspection {
                layout: ReadAtJournalLayout {
                    accepted_len: offset,
                    record_count,
                    leading_checkpoint,
                },
                accepted_prefix_digest: Digest::new(prefix_hasher.finalize().into()),
                repair: ((offset as u64) < source_len)
                    .then_some(JournalRepair::UnanchoredSuffix { offset }),
            }));
        }
    }

    Ok(None)
}

/// Rereads one bounded record envelope from an anchored source prefix.
///
/// This helper intentionally does not hash or copy the record body. The
/// preceding anchored scan already authenticated the record under the same
/// snapshot token; replay only needs fixed metadata, the trailing digest, and
/// either a bounded ordinary-command payload or the checkpoint state range.
pub(crate) fn read_at_record_location<S: JournalRecoverySource>(
    source: &mut S,
    snapshot: recovery_source::RecoverySourceSnapshot<S::Snapshot>,
    offset: usize,
    scratch: &mut [u8],
) -> Result<ReadAtRecordLocation, AnchoredJournalInspectionError<S::Error>> {
    let mut header = [0u8; 16];
    read_source_exact(source, snapshot, offset, &mut header, scratch)?;
    reject_read_at_record_magic_prefix(&header, offset)?;
    if read_u16(&header, 8) != JOURNAL_SCHEMA_VERSION {
        return Err(AnchoredJournalInspectionError::Journal(
            JournalDecodeError::UnsupportedVersion {
                version: read_u16(&header, 8),
            },
        ));
    }
    if read_u16(&header, 10) != JOURNAL_CORE_API_PROFILE {
        return Err(AnchoredJournalInspectionError::Journal(
            JournalDecodeError::UnsupportedApiProfile {
                profile: read_u16(&header, 10),
            },
        ));
    }
    let total_len = read_u32(&header, 12) as usize;
    if !(MIN_RECORD_LEN..=MAX_JOURNAL_RECORD_BYTES).contains(&total_len) {
        return Err(AnchoredJournalInspectionError::Journal(
            JournalDecodeError::InvalidLength,
        ));
    }
    let record_end = offset.checked_add(total_len).ok_or_else(|| {
        AnchoredJournalInspectionError::Journal(JournalDecodeError::LengthOverflow)
    })?;
    if u64::try_from(record_end)
        .ok()
        .is_none_or(|end| end > snapshot.logical_len())
    {
        return Err(AnchoredJournalInspectionError::Journal(
            JournalDecodeError::InvalidLength,
        ));
    }

    let mut fixed = [0u8; FIXED_WITHOUT_DIGEST];
    read_source_exact(source, snapshot, offset, &mut fixed, scratch)?;
    let payload_len = read_u32(&fixed, 176) as usize;
    if payload_len > MAX_COMMAND_PAYLOAD_BYTES
        || FIXED_WITHOUT_DIGEST
            .checked_add(payload_len)
            .and_then(|value| value.checked_add(DIGEST_LEN))
            != Some(total_len)
    {
        return Err(AnchoredJournalInspectionError::Journal(
            JournalDecodeError::InvalidLength,
        ));
    }
    let profile = read_profile(&fixed, 32)
        .map_err(|_| AnchoredJournalInspectionError::Journal(JournalDecodeError::InvalidLength))?;
    let world = WorldId::new(read_u64(&fixed, 40))
        .map_err(|_| AnchoredJournalInspectionError::Journal(JournalDecodeError::ZeroIdentity))?;
    let catalog_digest =
        Digest::new(fixed[48..80].try_into().map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::InvalidLength)
        })?);
    let registry = RegistryInstance::new(read_u64(&fixed, 80))
        .map_err(|_| AnchoredJournalInspectionError::Journal(JournalDecodeError::ZeroIdentity))?;
    let boot = BootGeneration::new(read_u64(&fixed, 88))
        .map_err(|_| AnchoredJournalInspectionError::Journal(JournalDecodeError::ZeroIdentity))?;
    let journal = JournalGeneration::new(read_u64(&fixed, 96))
        .map_err(|_| AnchoredJournalInspectionError::Journal(JournalDecodeError::ZeroIdentity))?;
    let device = DeviceGeneration::new(read_u64(&fixed, 104))
        .map_err(|_| AnchoredJournalInspectionError::Journal(JournalDecodeError::ZeroIdentity))?;
    let base_projection =
        Digest::new(fixed[112..144].try_into().map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::InvalidLength)
        })?);
    let binding = RecoveryBinding::new(profile, world, catalog_digest, registry)
        .map_err(|_| AnchoredJournalInspectionError::Journal(JournalDecodeError::InvalidBinding))?;
    let predecessor =
        Digest::new(fixed[144..176].try_into().map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::InvalidLength)
        })?);
    let meta = JournalRecordMeta {
        base_revision: read_u64(&fixed, 16),
        revision: read_u64(&fixed, 24),
        freshness: crate::Freshness::new(boot, registry, device, journal),
        binding,
        base_projection,
        predecessor,
    };
    let digest_offset = record_end.checked_sub(DIGEST_LEN).ok_or_else(|| {
        AnchoredJournalInspectionError::Journal(JournalDecodeError::LengthOverflow)
    })?;
    let mut digest_bytes = [0u8; DIGEST_LEN];
    read_source_exact(source, snapshot, digest_offset, &mut digest_bytes, scratch)?;
    let mut tag = [0u8; 1];
    read_source_exact(
        source,
        snapshot,
        offset + FIXED_WITHOUT_DIGEST,
        &mut tag,
        scratch,
    )?;
    let checkpoint = (tag[0] == 37).then(|| {
        inspect_read_at_checkpoint_payload(
            source,
            snapshot,
            offset,
            total_len,
            payload_len,
            scratch,
        )
    });
    let checkpoint = match checkpoint {
        Some(result) => Some(result?),
        None => None,
    };
    Ok(ReadAtRecordLocation {
        offset,
        total_len,
        payload_offset: offset + FIXED_WITHOUT_DIGEST,
        payload_len,
        meta,
        digest: Digest::new(digest_bytes),
        checkpoint,
    })
}

fn map_read_at_inspection_error<E>(error: ReadAtError<E>) -> AnchoredJournalInspectionError<E> {
    match error {
        ReadAtError::EmptyScratch => AnchoredJournalInspectionError::EmptyScratch,
        ReadAtError::OutOfRange => {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::InvalidLength)
        }
        ReadAtError::Source(error) => AnchoredJournalInspectionError::Source(error),
    }
}

fn read_source_exact<S: JournalRecoverySource>(
    source: &mut S,
    snapshot: recovery_source::RecoverySourceSnapshot<S::Snapshot>,
    offset: usize,
    output: &mut [u8],
    scratch: &mut [u8],
) -> Result<(), AnchoredJournalInspectionError<S::Error>> {
    let mut cursor = ReadAtCursor::new(
        source,
        snapshot.token(),
        snapshot.logical_len(),
        offset as u64,
        output.len() as u64,
        scratch,
    )
    .map_err(map_read_at_inspection_error)?;
    cursor
        .read_exact(output)
        .map_err(map_read_at_inspection_error)
}

fn inspect_read_at_checkpoint_payload<S: JournalRecoverySource>(
    source: &mut S,
    snapshot: recovery_source::RecoverySourceSnapshot<S::Snapshot>,
    record_offset: usize,
    record_len: usize,
    payload_len: usize,
    scratch: &mut [u8],
) -> Result<ReadAtCheckpointLocation, AnchoredJournalInspectionError<S::Error>> {
    const CHECKPOINT_PAYLOAD_FIXED: usize = 1 + DIGEST_LEN + 4;
    if payload_len < CHECKPOINT_PAYLOAD_FIXED {
        return Err(AnchoredJournalInspectionError::Journal(
            JournalDecodeError::Command(CommandDecodeError::UnexpectedEof),
        ));
    }
    let payload_offset = record_offset + FIXED_WITHOUT_DIGEST;
    let mut fixed = [0u8; CHECKPOINT_PAYLOAD_FIXED];
    read_source_exact(source, snapshot, payload_offset, &mut fixed, scratch)?;
    let projection =
        Digest::new(fixed[1..1 + DIGEST_LEN].try_into().map_err(|_| {
            AnchoredJournalInspectionError::Journal(JournalDecodeError::InvalidLength)
        })?);
    let state_len = read_u32(&fixed, 1 + DIGEST_LEN) as usize;
    if state_len > MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES {
        return Err(AnchoredJournalInspectionError::Journal(
            JournalDecodeError::Command(CommandDecodeError::UnexpectedEof),
        ));
    }
    if CHECKPOINT_PAYLOAD_FIXED.checked_add(state_len) != Some(payload_len) {
        return Err(AnchoredJournalInspectionError::Journal(
            JournalDecodeError::Command(if payload_len < CHECKPOINT_PAYLOAD_FIXED + state_len {
                CommandDecodeError::UnexpectedEof
            } else {
                CommandDecodeError::TrailingBytes
            }),
        ));
    }
    Ok(ReadAtCheckpointLocation {
        record_offset,
        record_len,
        state_offset: payload_offset + CHECKPOINT_PAYLOAD_FIXED,
        state_len,
        projection,
    })
}

fn reject_read_at_record_magic_prefix<E>(
    fixed: &[u8; 16],
    offset: usize,
) -> Result<(), AnchoredJournalInspectionError<E>> {
    let version = match &fixed[..8] {
        magic if magic == JOURNAL_MAGIC => return Ok(()),
        magic if magic == PREVIOUS_JOURNAL_MAGIC => PREVIOUS_JOURNAL_SCHEMA_VERSION,
        magic if magic == PREVIOUS_PREVIOUS_JOURNAL_MAGIC => {
            PREVIOUS_PREVIOUS_JOURNAL_SCHEMA_VERSION
        }
        magic if magic == PRE_HANDOFF_RESOLUTION_JOURNAL_MAGIC => {
            PRE_HANDOFF_RESOLUTION_JOURNAL_SCHEMA_VERSION
        }
        magic if magic == PROFILE_ONE_JOURNAL_MAGIC => PROFILE_ONE_JOURNAL_SCHEMA_VERSION,
        magic if magic == LEGACY_JOURNAL_MAGIC => LEGACY_JOURNAL_SCHEMA_VERSION,
        _ => {
            return Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::BadMagic { offset },
            ));
        }
    };
    Err(AnchoredJournalInspectionError::Journal(
        JournalDecodeError::UnsupportedVersion { version },
    ))
}

/// Returns the schema version for a recognized predecessor journal magic.
///
/// This deliberately examines only the fixed magic prefix. Host recovery can
/// reject a legacy journal while the trusted anchor names genesis without
/// materializing an unbounded failed-write suffix.
#[cfg(feature = "std")]
pub(crate) fn recognized_legacy_journal_version(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < JOURNAL_MAGIC.len() {
        return None;
    }
    match &bytes[..JOURNAL_MAGIC.len()] {
        b"CSERJ11\0" => Some(PREVIOUS_JOURNAL_SCHEMA_VERSION),
        b"CSERJR9\0" => Some(PREVIOUS_PREVIOUS_JOURNAL_SCHEMA_VERSION),
        b"CSERJR8\0" => Some(8),
        b"CSERJR7\0" => Some(PRE_HANDOFF_RESOLUTION_JOURNAL_SCHEMA_VERSION),
        b"CSERJR6\0" => Some(6),
        b"CSERJR5\0" => Some(PROFILE_ONE_JOURNAL_SCHEMA_VERSION),
        b"CSERJR4\0" => Some(LEGACY_JOURNAL_SCHEMA_VERSION),
        _ => None,
    }
}

/// Validates a record envelope header and returns its bounded total length.
///
/// The caller must still read and validate the complete record with
/// [`scan_journal`]. This helper only admits the fixed header grammar before
/// allocating for an attacker-controlled record body.
#[cfg(feature = "std")]
pub(crate) fn journal_record_total_len(
    header: &[u8; JOURNAL_RECORD_HEADER_LEN],
) -> Result<usize, JournalDecodeError> {
    if let Some(version) = recognized_legacy_journal_version(header) {
        return Err(JournalDecodeError::UnsupportedVersion { version });
    }
    if header[..8] != JOURNAL_MAGIC {
        return Err(JournalDecodeError::BadMagic { offset: 0 });
    }
    let version = read_u16(header, 8);
    if version != JOURNAL_SCHEMA_VERSION {
        return Err(JournalDecodeError::UnsupportedVersion { version });
    }
    let profile = read_u16(header, 10);
    if profile != JOURNAL_CORE_API_PROFILE {
        return Err(JournalDecodeError::UnsupportedApiProfile { profile });
    }
    let total_len = read_u32(header, 12) as usize;
    if !(MIN_RECORD_LEN..=MAX_JOURNAL_RECORD_BYTES).contains(&total_len) {
        return Err(JournalDecodeError::InvalidLength);
    }
    Ok(total_len)
}

/// Decodes exactly one structurally valid record as a borrowed view.
///
/// This helper does not construct a [`JournalRecord`], clone the encoded
/// bytes, or allocate a checkpoint image. The caller validates the returned
/// metadata against the preceding record when reading an anchored stream
/// incrementally.
#[cfg(feature = "std")]
pub(crate) fn decode_journal_record_borrowed(
    bytes: &[u8],
) -> Result<JournalRecordView<'_>, JournalDecodeError> {
    let (scan, _) = scan_journal_views_inner(bytes, None, false)?;
    if scan.records.len() != 1 || scan.torn_tail.is_some() {
        return Err(JournalDecodeError::InvalidLength);
    }
    scan.records
        .into_iter()
        .next()
        .ok_or(JournalDecodeError::InvalidLength)
}

fn scan_journal_inner(
    bytes: &[u8],
    expected_head: Option<Digest>,
) -> Result<(JournalScan, bool), JournalDecodeError> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    let mut previous: Option<(u64, Digest)> = None;
    while offset < bytes.len() {
        if records.len() >= MAX_JOURNAL_SCAN_RECORDS {
            return Err(JournalDecodeError::RecordCountExceeded {
                limit: MAX_JOURNAL_SCAN_RECORDS,
            });
        }
        let remaining = &bytes[offset..];
        if remaining.len() < JOURNAL_MAGIC.len() {
            return Ok((
                JournalScan {
                    records,
                    torn_tail: Some(offset),
                    unanchored_suffix: None,
                },
                false,
            ));
        }
        if remaining[..8] == PRE_HANDOFF_RESOLUTION_JOURNAL_MAGIC {
            return Err(JournalDecodeError::UnsupportedVersion {
                version: PRE_HANDOFF_RESOLUTION_JOURNAL_SCHEMA_VERSION,
            });
        }
        if remaining[..8] == PREVIOUS_JOURNAL_MAGIC {
            return Err(JournalDecodeError::UnsupportedVersion {
                version: PREVIOUS_JOURNAL_SCHEMA_VERSION,
            });
        }
        if remaining[..8] == PREVIOUS_PREVIOUS_JOURNAL_MAGIC {
            return Err(JournalDecodeError::UnsupportedVersion {
                version: PREVIOUS_PREVIOUS_JOURNAL_SCHEMA_VERSION,
            });
        }
        if remaining[..8] == PROFILE_ONE_JOURNAL_MAGIC {
            return Err(JournalDecodeError::UnsupportedVersion {
                version: PROFILE_ONE_JOURNAL_SCHEMA_VERSION,
            });
        }
        if remaining[..8] == LEGACY_JOURNAL_MAGIC {
            return Err(JournalDecodeError::UnsupportedVersion {
                version: LEGACY_JOURNAL_SCHEMA_VERSION,
            });
        }
        if remaining.len() < 16 {
            return Ok((
                JournalScan {
                    records,
                    torn_tail: Some(offset),
                    unanchored_suffix: None,
                },
                false,
            ));
        }
        if remaining[..8] != JOURNAL_MAGIC {
            return Err(JournalDecodeError::BadMagic { offset });
        }
        let version = read_u16(remaining, 8);
        if version != JOURNAL_SCHEMA_VERSION {
            return Err(JournalDecodeError::UnsupportedVersion { version });
        }
        let profile = read_u16(remaining, 10);
        if profile != JOURNAL_CORE_API_PROFILE {
            return Err(JournalDecodeError::UnsupportedApiProfile { profile });
        }
        let total_len = read_u32(remaining, 12) as usize;
        if total_len < MIN_RECORD_LEN {
            return Err(JournalDecodeError::InvalidLength);
        }
        if total_len > MAX_JOURNAL_RECORD_BYTES {
            return Err(JournalDecodeError::InvalidLength);
        }
        if offset > MAX_JOURNAL_SCAN_BYTES - total_len {
            return Err(JournalDecodeError::InputTooLarge {
                limit: MAX_JOURNAL_SCAN_BYTES,
            });
        }
        if remaining.len() < total_len {
            return Ok((
                JournalScan {
                    records,
                    torn_tail: Some(offset),
                    unanchored_suffix: None,
                },
                false,
            ));
        }
        let record_bytes = &remaining[..total_len];
        let payload_len = read_u32(record_bytes, 176) as usize;
        if payload_len > MAX_COMMAND_PAYLOAD_BYTES {
            return Err(JournalDecodeError::Command(
                CommandDecodeError::PayloadTooLarge,
            ));
        }
        if FIXED_WITHOUT_DIGEST
            .checked_add(payload_len)
            .and_then(|value| value.checked_add(DIGEST_LEN))
            != Some(total_len)
        {
            return Err(JournalDecodeError::InvalidLength);
        }
        let expected = Digest::new(
            record_bytes[total_len - DIGEST_LEN..]
                .try_into()
                .map_err(|_| JournalDecodeError::InvalidLength)?,
        );
        let actual = Digest::new(Sha256::digest(&record_bytes[..total_len - DIGEST_LEN]).into());
        if expected != actual {
            return Err(JournalDecodeError::ChecksumMismatch { offset });
        }

        let profile =
            read_profile(record_bytes, 32).map_err(|_| JournalDecodeError::InvalidLength)?;
        if profile != RecoveryProfile::current() {
            return Err(JournalDecodeError::UnsupportedApiProfile {
                profile: profile.core_api(),
            });
        }
        let world = WorldId::new(read_u64(record_bytes, 40))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let catalog_digest = Digest::new(
            record_bytes[48..80]
                .try_into()
                .map_err(|_| JournalDecodeError::InvalidLength)?,
        );
        let registry = RegistryInstance::new(read_u64(record_bytes, 80))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let boot = BootGeneration::new(read_u64(record_bytes, 88))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let journal = JournalGeneration::new(read_u64(record_bytes, 96))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let device = DeviceGeneration::new(read_u64(record_bytes, 104))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let base_projection = Digest::new(
            record_bytes[112..144]
                .try_into()
                .map_err(|_| JournalDecodeError::InvalidLength)?,
        );
        if base_projection.is_zero() {
            return Err(JournalDecodeError::InvalidBinding);
        }
        RecoveryBinding::new(profile, world, catalog_digest, registry)
            .map_err(|_| JournalDecodeError::InvalidBinding)?;
        let predecessor = Digest::new(
            record_bytes[144..176]
                .try_into()
                .map_err(|_| JournalDecodeError::InvalidLength)?,
        );
        let payload = &record_bytes[FIXED_WITHOUT_DIGEST..total_len - DIGEST_LEN];
        let command = CommandKind::decode_payload(payload).map_err(JournalDecodeError::Command)?;
        let base_revision = read_u64(record_bytes, 16);
        let revision = read_u64(record_bytes, 24);
        if expected_head.is_some() {
            if let Some((previous_revision, previous_head)) = previous {
                validate_record_successor(
                    base_revision,
                    revision,
                    predecessor,
                    previous_revision,
                    previous_head,
                    offset,
                )?;
            } else {
                validate_record_start(
                    base_revision,
                    revision,
                    predecessor,
                    matches!(&command, CommandKind::WholeStateCheckpointV1 { .. }),
                    offset,
                )?;
            }
        }

        records.push(JournalRecord {
            base_revision,
            revision,
            boot,
            registry,
            journal,
            device,
            profile,
            world,
            catalog_digest,
            base_projection,
            predecessor,
            command,
            digest: expected,
            bytes: Arc::from(record_bytes.to_vec().into_boxed_slice()),
        });
        offset = offset
            .checked_add(total_len)
            .ok_or(JournalDecodeError::LengthOverflow)?;
        previous = Some((revision, expected));
        if expected_head == Some(expected) {
            return Ok((
                JournalScan {
                    records,
                    torn_tail: None,
                    unanchored_suffix: (offset < bytes.len()).then_some(offset),
                },
                true,
            ));
        }
    }

    Ok((
        JournalScan {
            records,
            torn_tail: None,
            unanchored_suffix: None,
        },
        false,
    ))
}

/// Applies the same chain checks to an owned full scan after its bounded
/// records have been materialized. Keeping this pass after structural scan
/// preserves the scan budget's record-count error precedence while still
/// rejecting every checksum-valid discontinuity before a caller can replay
/// the records.
fn validate_owned_chain(records: &[JournalRecord]) -> Result<(), JournalDecodeError> {
    let Some(first) = records.first() else {
        return Ok(());
    };
    // A full structural scan may be used to inspect a standalone record
    // captured before an anchor was available. It still enforces each
    // record's self-consistent revision, while the anchored scanner below
    // additionally enforces genesis/checkpoint start semantics.
    validate_record_revision(first.base_revision, first.revision, 0)?;
    let mut offset = records[0].bytes.len();
    for pair in records.windows(2) {
        validate_record_successor(
            pair[1].base_revision,
            pair[1].revision,
            pair[1].predecessor,
            pair[0].revision,
            pair[0].digest,
            offset,
        )?;
        offset = offset.saturating_add(pair[1].bytes.len());
    }
    Ok(())
}

/// Validates the revision relation carried by one decoded record.
///
/// This check is deliberately shared by the owned and borrowed scanners. A
/// checksum authenticates the bytes, but it does not make a tampered revision
/// a valid transition in the hash chain.
fn validate_record_revision(
    base_revision: u64,
    revision: u64,
    offset: usize,
) -> Result<(), JournalDecodeError> {
    let expected = base_revision
        .checked_add(1)
        .ok_or(JournalDecodeError::RevisionOverflow)?;
    if revision != expected {
        return Err(JournalDecodeError::ChainMismatch { offset });
    }
    Ok(())
}

/// Validates the first record in a journal prefix.
fn validate_record_start(
    base_revision: u64,
    revision: u64,
    predecessor: Digest,
    is_checkpoint: bool,
    offset: usize,
) -> Result<(), JournalDecodeError> {
    validate_record_revision(base_revision, revision, offset)?;
    if !is_checkpoint && (base_revision != 0 || !predecessor.is_zero()) {
        return Err(JournalDecodeError::ChainMismatch { offset });
    }
    Ok(())
}

/// Validates one record against the immediately preceding record.
fn validate_record_successor(
    base_revision: u64,
    revision: u64,
    predecessor: Digest,
    previous_revision: u64,
    previous_head: Digest,
    offset: usize,
) -> Result<(), JournalDecodeError> {
    validate_record_revision(base_revision, revision, offset)?;
    if base_revision != previous_revision || predecessor != previous_head {
        return Err(JournalDecodeError::ChainMismatch { offset });
    }
    Ok(())
}

/// Validates one payload while preserving checkpoint bytes as a borrowed
/// range.  The existing command decoder is still used for every ordinary
/// command, so the new scanner does not accept a payload which the owned
/// scanner would reject.
fn validate_borrowed_payload(
    payload: &[u8],
) -> Result<Option<(Digest, usize, usize)>, JournalDecodeError> {
    if payload.first().copied() != Some(37) {
        CommandKind::decode_payload(payload).map_err(JournalDecodeError::Command)?;
        return Ok(None);
    }

    // WholeStateCheckpointV1 is tag + projection + state length + state.
    const CHECKPOINT_PAYLOAD_FIXED: usize = 1 + DIGEST_LEN + 4;
    if payload.len() < CHECKPOINT_PAYLOAD_FIXED {
        return Err(JournalDecodeError::Command(
            CommandDecodeError::UnexpectedEof,
        ));
    }
    let projection = Digest::new(
        payload[1..1 + DIGEST_LEN]
            .try_into()
            .map_err(|_| JournalDecodeError::InvalidLength)?,
    );
    let state_len = read_u32(payload, 1 + DIGEST_LEN) as usize;
    if state_len > MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES {
        // Keep parity with CommandKind::decode_payload, which reports this
        // bounded image failure as an unexpected end of its cursor.
        return Err(JournalDecodeError::Command(
            CommandDecodeError::UnexpectedEof,
        ));
    }
    let state_start = CHECKPOINT_PAYLOAD_FIXED;
    let state_end = state_start
        .checked_add(state_len)
        .ok_or(JournalDecodeError::LengthOverflow)?;
    if payload.len() < state_end {
        return Err(JournalDecodeError::Command(
            CommandDecodeError::UnexpectedEof,
        ));
    }
    if payload.len() != state_end {
        return Err(JournalDecodeError::Command(
            CommandDecodeError::TrailingBytes,
        ));
    }
    Ok(Some((projection, state_start, state_len)))
}

fn scan_journal_views_inner(
    bytes: &[u8],
    expected_head: Option<Digest>,
    enforce_start: bool,
) -> Result<(JournalScanView<'_>, bool), JournalDecodeError> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    let mut previous: Option<(u64, Digest)> = None;

    while offset < bytes.len() {
        if records.len() >= MAX_JOURNAL_SCAN_RECORDS {
            return Err(JournalDecodeError::RecordCountExceeded {
                limit: MAX_JOURNAL_SCAN_RECORDS,
            });
        }
        let remaining = &bytes[offset..];
        if remaining.len() < JOURNAL_MAGIC.len() {
            return Ok((
                JournalScanView {
                    records,
                    torn_tail: Some(offset),
                    unanchored_suffix: None,
                },
                false,
            ));
        }
        if remaining[..8] == PRE_HANDOFF_RESOLUTION_JOURNAL_MAGIC {
            return Err(JournalDecodeError::UnsupportedVersion {
                version: PRE_HANDOFF_RESOLUTION_JOURNAL_SCHEMA_VERSION,
            });
        }
        if remaining[..8] == PREVIOUS_JOURNAL_MAGIC {
            return Err(JournalDecodeError::UnsupportedVersion {
                version: PREVIOUS_JOURNAL_SCHEMA_VERSION,
            });
        }
        if remaining[..8] == PREVIOUS_PREVIOUS_JOURNAL_MAGIC {
            return Err(JournalDecodeError::UnsupportedVersion {
                version: PREVIOUS_PREVIOUS_JOURNAL_SCHEMA_VERSION,
            });
        }
        if remaining[..8] == PROFILE_ONE_JOURNAL_MAGIC {
            return Err(JournalDecodeError::UnsupportedVersion {
                version: PROFILE_ONE_JOURNAL_SCHEMA_VERSION,
            });
        }
        if remaining[..8] == LEGACY_JOURNAL_MAGIC {
            return Err(JournalDecodeError::UnsupportedVersion {
                version: LEGACY_JOURNAL_SCHEMA_VERSION,
            });
        }
        if remaining.len() < 16 {
            return Ok((
                JournalScanView {
                    records,
                    torn_tail: Some(offset),
                    unanchored_suffix: None,
                },
                false,
            ));
        }
        if remaining[..8] != JOURNAL_MAGIC {
            return Err(JournalDecodeError::BadMagic { offset });
        }
        let version = read_u16(remaining, 8);
        if version != JOURNAL_SCHEMA_VERSION {
            return Err(JournalDecodeError::UnsupportedVersion { version });
        }
        let envelope_profile = read_u16(remaining, 10);
        if envelope_profile != JOURNAL_CORE_API_PROFILE {
            return Err(JournalDecodeError::UnsupportedApiProfile {
                profile: envelope_profile,
            });
        }
        let total_len = read_u32(remaining, 12) as usize;
        if !(MIN_RECORD_LEN..=MAX_JOURNAL_RECORD_BYTES).contains(&total_len) {
            return Err(JournalDecodeError::InvalidLength);
        }
        if offset > MAX_JOURNAL_SCAN_BYTES - total_len {
            return Err(JournalDecodeError::InputTooLarge {
                limit: MAX_JOURNAL_SCAN_BYTES,
            });
        }
        if remaining.len() < total_len {
            return Ok((
                JournalScanView {
                    records,
                    torn_tail: Some(offset),
                    unanchored_suffix: None,
                },
                false,
            ));
        }

        let record_bytes = &remaining[..total_len];
        let payload_len = read_u32(record_bytes, 176) as usize;
        if payload_len > MAX_COMMAND_PAYLOAD_BYTES {
            return Err(JournalDecodeError::Command(
                CommandDecodeError::PayloadTooLarge,
            ));
        }
        if FIXED_WITHOUT_DIGEST
            .checked_add(payload_len)
            .and_then(|value| value.checked_add(DIGEST_LEN))
            != Some(total_len)
        {
            return Err(JournalDecodeError::InvalidLength);
        }
        let expected = Digest::new(
            record_bytes[total_len - DIGEST_LEN..]
                .try_into()
                .map_err(|_| JournalDecodeError::InvalidLength)?,
        );
        let actual = Digest::new(Sha256::digest(&record_bytes[..total_len - DIGEST_LEN]).into());
        if expected != actual {
            return Err(JournalDecodeError::ChecksumMismatch { offset });
        }

        let profile =
            read_profile(record_bytes, 32).map_err(|_| JournalDecodeError::InvalidLength)?;
        if profile != RecoveryProfile::current() {
            return Err(JournalDecodeError::UnsupportedApiProfile {
                profile: profile.core_api(),
            });
        }
        let world = WorldId::new(read_u64(record_bytes, 40))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let catalog_digest = Digest::new(
            record_bytes[48..80]
                .try_into()
                .map_err(|_| JournalDecodeError::InvalidLength)?,
        );
        let registry = RegistryInstance::new(read_u64(record_bytes, 80))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let boot = BootGeneration::new(read_u64(record_bytes, 88))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let journal = JournalGeneration::new(read_u64(record_bytes, 96))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let device = DeviceGeneration::new(read_u64(record_bytes, 104))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let base_projection = Digest::new(
            record_bytes[112..144]
                .try_into()
                .map_err(|_| JournalDecodeError::InvalidLength)?,
        );
        if base_projection.is_zero() {
            return Err(JournalDecodeError::InvalidBinding);
        }
        let binding = RecoveryBinding::new(profile, world, catalog_digest, registry)
            .map_err(|_| JournalDecodeError::InvalidBinding)?;
        let predecessor = Digest::new(
            record_bytes[144..176]
                .try_into()
                .map_err(|_| JournalDecodeError::InvalidLength)?,
        );
        let meta = JournalRecordMeta {
            base_revision: read_u64(record_bytes, 16),
            revision: read_u64(record_bytes, 24),
            freshness: crate::Freshness::new(boot, registry, device, journal),
            binding,
            base_projection,
            predecessor,
        };
        let payload = &record_bytes[FIXED_WITHOUT_DIGEST..total_len - DIGEST_LEN];
        let checkpoint = validate_borrowed_payload(payload)?;
        if let Some((revision, head)) = previous {
            validate_record_successor(
                meta.base_revision,
                meta.revision,
                meta.predecessor,
                revision,
                head,
                offset,
            )?;
        } else if enforce_start {
            validate_record_start(
                meta.base_revision,
                meta.revision,
                meta.predecessor,
                checkpoint.is_some(),
                offset,
            )?;
        }

        let (checkpoint_projection, checkpoint_state_start, checkpoint_state_len) = checkpoint
            .map_or((None, 0, 0), |(projection, state_start, state_len)| {
                (
                    Some(projection),
                    offset + FIXED_WITHOUT_DIGEST + state_start,
                    state_len,
                )
            });
        records.push(JournalRecordView {
            input: bytes,
            offset,
            total_len,
            payload_len,
            meta,
            digest: expected,
            checkpoint_projection,
            checkpoint_state_start,
            checkpoint_state_len,
        });
        offset = offset
            .checked_add(total_len)
            .ok_or(JournalDecodeError::LengthOverflow)?;
        previous = Some((meta.revision, expected));
        if expected_head == Some(expected) {
            return Ok((
                JournalScanView {
                    records,
                    torn_tail: None,
                    unanchored_suffix: (offset < bytes.len()).then_some(offset),
                },
                true,
            ));
        }
    }

    Ok((
        JournalScanView {
            records,
            torn_tail: None,
            unanchored_suffix: None,
        },
        false,
    ))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed envelope field"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed envelope field"),
    )
}

#[cfg(test)]
mod checkpoint_tests {
    use alloc::vec;

    use super::*;
    use crate::{CatalogSet, CoreError, CoreLimits, Engine, RecoveryAnchor, standard_catalog};

    fn binding(catalog: &crate::DomainCatalog) -> crate::RecoveryBinding {
        crate::RecoveryBinding::new(
            crate::RecoveryProfile::current(),
            crate::WorldId::new(1).unwrap(),
            catalog.digest(),
            crate::RegistryInstance::new(1).unwrap(),
        )
        .unwrap()
    }

    fn freshness(boot: u64, journal: u64) -> crate::Freshness {
        crate::Freshness::new(
            crate::BootGeneration::new(boot).unwrap(),
            crate::RegistryInstance::new(1).unwrap(),
            crate::DeviceGeneration::new(1).unwrap(),
            crate::JournalGeneration::new(journal).unwrap(),
        )
    }

    #[test]
    fn recovery_rejects_a_checksum_valid_checkpoint_with_wrong_projection() {
        let catalog = standard_catalog();
        let engine = Engine::new(
            crate::WorldId::new(1).unwrap(),
            CatalogSet::new(core::slice::from_ref(&catalog)).unwrap(),
            CoreLimits::bounded_default(),
            freshness(1, 1),
        );
        let checkpoint = JournalCheckpoint::build(
            binding(&catalog),
            freshness(1, 1),
            0,
            Digest::ZERO,
            Digest::new([7; 32]),
            &[],
        )
        .unwrap();
        assert!(matches!(
            checkpoint.recover(
                CatalogSet::new(core::slice::from_ref(&catalog)).unwrap(),
                CoreLimits::bounded_default(),
                RecoveryAnchor::from_trusted_provider(
                    binding(&catalog),
                    freshness(1, 1),
                    freshness(2, 2),
                    0,
                    Digest::ZERO,
                    engine.projection_digest(),
                )
                .unwrap(),
            ),
            Err(CoreError::RollbackDetected)
        ));
        assert_ne!(engine.projection_digest(), Digest::new([7; 32]));
    }

    #[test]
    fn recovery_validates_checkpoint_once_then_keeps_trusted_projection_overlay() {
        let catalog = standard_catalog();
        let catalogs = CatalogSet::new(core::slice::from_ref(&catalog)).unwrap();
        let committed = freshness(1, 1);
        let next = freshness(2, 2);
        let checkpoint_binding = crate::RecoveryBinding::new(
            crate::RecoveryProfile::current(),
            crate::WorldId::new(1).unwrap(),
            catalogs.digest(),
            crate::RegistryInstance::new(1).unwrap(),
        )
        .unwrap();
        let engine = Engine::new(
            crate::WorldId::new(1).unwrap(),
            catalogs.clone(),
            CoreLimits::bounded_default(),
            committed,
        );
        let checkpoint = JournalCheckpoint::build(
            checkpoint_binding,
            committed,
            0,
            Digest::ZERO,
            engine.projection_digest(),
            &[],
        )
        .unwrap();
        let anchor = RecoveryAnchor::from_trusted_provider(
            checkpoint_binding,
            committed,
            next,
            0,
            Digest::ZERO,
            engine.projection_digest(),
        )
        .unwrap();

        let report = checkpoint
            .recover(catalogs, CoreLimits::bounded_default(), anchor)
            .unwrap();
        assert_eq!(report.acknowledged_revision(), 0);
        assert_eq!(report.acknowledged_head(), Digest::ZERO);
        let recovered = report.into_engine();
        assert_eq!(recovered.projection_digest(), engine.projection_digest());
        assert_eq!(recovered.freshness(), committed);
        assert_eq!(
            recovered.journal_checkpoint(&[]),
            Err(crate::CoreError::RecoveryPending)
        );
    }

    #[test]
    fn recovery_rejects_a_valid_envelope_with_a_malicious_image() {
        let catalog = standard_catalog();
        let catalogs = CatalogSet::new(core::slice::from_ref(&catalog)).unwrap();
        let committed = freshness(1, 1);
        let engine = Engine::new(
            crate::WorldId::new(1).unwrap(),
            catalogs.clone(),
            CoreLimits::bounded_default(),
            committed,
        );
        let checkpoint_binding = crate::RecoveryBinding::new(
            crate::RecoveryProfile::current(),
            crate::WorldId::new(1).unwrap(),
            catalogs.digest(),
            crate::RegistryInstance::new(1).unwrap(),
        )
        .unwrap();
        let checkpoint = JournalCheckpoint::build(
            checkpoint_binding,
            committed,
            0,
            Digest::ZERO,
            engine.projection_digest(),
            b"malicious-image",
        )
        .unwrap();
        let anchor = RecoveryAnchor::from_trusted_provider(
            checkpoint_binding,
            committed,
            freshness(2, 2),
            0,
            Digest::ZERO,
            engine.projection_digest(),
        )
        .unwrap();

        assert!(matches!(
            checkpoint.recover(catalogs, CoreLimits::bounded_default(), anchor),
            Err(crate::CoreError::RollbackDetected)
        ));
    }

    #[test]
    fn decode_rejects_oversized_image_before_checksum_validation() {
        let total = CHECKPOINT_MIN_LEN + MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES + 1;
        let mut bytes = vec![0u8; total];
        bytes[..8].copy_from_slice(&JOURNAL_CHECKPOINT_MAGIC);
        bytes[8..10].copy_from_slice(&JOURNAL_CHECKPOINT_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&JOURNAL_CORE_API_PROFILE.to_le_bytes());
        bytes[12..16].copy_from_slice(&(u32::try_from(total).unwrap()).to_le_bytes());
        bytes[176..180].copy_from_slice(
            &(u32::try_from(MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES + 1).unwrap()).to_le_bytes(),
        );
        assert_eq!(
            JournalCheckpoint::decode(&bytes),
            Err(JournalCheckpointDecodeError::ImageTooLarge)
        );
    }

    #[test]
    fn decode_identifies_checkpoint_four_before_vnext_length_checks() {
        let mut bytes = vec![0u8; 196];
        bytes[..8].copy_from_slice(&PREVIOUS_CHECKPOINT_MAGIC);
        assert_eq!(
            JournalCheckpoint::decode(&bytes),
            Err(JournalCheckpointDecodeError::UnsupportedVersion { version: 4 })
        );
    }

    #[test]
    fn decode_identifies_predecessor_journal_before_vnext_length_checks() {
        let mut bytes = vec![0u8; 16];
        bytes[..8].copy_from_slice(&PREVIOUS_JOURNAL_MAGIC);
        assert!(matches!(
            scan_journal(&bytes),
            Err(JournalDecodeError::UnsupportedVersion { version: 11 })
        ));
    }

    #[test]
    fn decode_identifies_the_older_checkpoint_before_vnext_length_checks() {
        let mut bytes = vec![0u8; 196];
        bytes[..8].copy_from_slice(&LEGACY_CHECKPOINT_MAGIC);
        assert_eq!(
            JournalCheckpoint::decode(&bytes),
            Err(JournalCheckpointDecodeError::UnsupportedVersion { version: 1 })
        );
    }
}

#[cfg(test)]
mod borrowed_view_tests {
    use alloc::{sync::Arc, vec};

    use super::*;

    fn digest(value: u8) -> Digest {
        Digest::new([value; 32])
    }

    fn freshness() -> crate::Freshness {
        crate::Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        )
    }

    fn binding() -> RecoveryBinding {
        RecoveryBinding::new(
            RecoveryProfile::current(),
            WorldId::new(1).unwrap(),
            digest(9),
            RegistryInstance::new(1).unwrap(),
        )
        .unwrap()
    }

    fn ordinary_record(base_revision: u64, predecessor: Digest) -> JournalRecord {
        JournalRecord::build(
            base_revision,
            freshness(),
            binding(),
            digest(7),
            predecessor,
            CommandKind::CheckpointRecovery {
                boot: BootGeneration::new(2).unwrap(),
                journal: JournalGeneration::new(2).unwrap(),
                device: DeviceGeneration::new(1).unwrap(),
            },
        )
        .unwrap()
    }

    fn checkpoint_record(base_revision: u64, predecessor: Digest, state: &[u8]) -> JournalRecord {
        JournalRecord::build(
            base_revision,
            freshness(),
            binding(),
            digest(7),
            predecessor,
            CommandKind::WholeStateCheckpointV1 {
                state: Arc::from(state.to_vec().into_boxed_slice()),
                projection: digest(8),
            },
        )
        .unwrap()
    }

    #[test]
    fn borrowed_checkpoint_view_keeps_input_slices_and_owned_meta_equivalence() {
        let record = checkpoint_record(4, digest(6), b"borrowed-checkpoint-state");
        let input = record.bytes().to_vec();
        let borrowed = scan_journal_to_head_borrowed(&input, record.digest())
            .unwrap()
            .unwrap();
        let view = borrowed.records().first().copied().unwrap();
        let owned = scan_journal(&input).unwrap();
        let owned_record = &owned.records()[0];

        assert_eq!(view.digest(), owned_record.digest());
        assert_eq!(view.meta().base_revision(), owned_record.base_revision());
        assert_eq!(view.meta().revision(), owned_record.revision());
        assert_eq!(
            view.meta().freshness(),
            crate::Freshness::new(
                owned_record.boot(),
                owned_record.registry(),
                owned_record.device(),
                owned_record.journal(),
            )
        );
        assert_eq!(view.payload(), &input[view.payload_range()]);

        let checkpoint = view
            .whole_state_checkpoint()
            .expect("checkpoint tag must be recognized without decoding");
        assert_eq!(checkpoint.projection(), digest(8));
        assert_eq!(checkpoint.state(), b"borrowed-checkpoint-state");
        assert_eq!(checkpoint.state(), &input[checkpoint.state_range()]);
        assert_eq!(
            checkpoint.state().as_ptr(),
            input[checkpoint.state_range()].as_ptr()
        );
    }

    #[test]
    fn borrowed_anchored_scan_stops_before_an_unanchored_suffix() {
        let first = ordinary_record(0, Digest::ZERO);
        let second = ordinary_record(1, first.digest());
        let mut input = first.bytes().to_vec();
        input.extend_from_slice(second.bytes());
        input.extend_from_slice(b"not-a-journal-record");

        let scan = scan_journal_to_head_borrowed(&input, first.digest())
            .unwrap()
            .unwrap();
        assert_eq!(scan.records().len(), 1);
        assert_eq!(scan.records()[0].digest(), first.digest());
        assert_eq!(scan.unanchored_suffix(), Some(first.bytes().len()));
        assert_eq!(scan.torn_tail(), None);
    }

    #[test]
    fn borrowed_anchored_scan_fails_closed_for_torn_corrupt_and_wrong_head() {
        let first = ordinary_record(0, Digest::ZERO);
        let second = ordinary_record(1, first.digest());

        let mut torn = first.bytes().to_vec();
        torn.extend_from_slice(&second.bytes()[..16]);
        assert!(
            scan_journal_to_head_borrowed(&torn, second.digest())
                .unwrap()
                .is_none(),
            "a torn record before the expected head cannot be accepted"
        );

        let mut corrupt = first.bytes().to_vec();
        corrupt[FIXED_WITHOUT_DIGEST - DIGEST_LEN] ^= 1;
        let corrupt_result = scan_journal_to_head_borrowed(&corrupt, first.digest());
        assert!(matches!(
            corrupt_result,
            Err(JournalDecodeError::ChecksumMismatch { offset: 0 })
        ));

        let mut valid_chain = first.bytes().to_vec();
        valid_chain.extend_from_slice(second.bytes());
        assert!(
            scan_journal_to_head_borrowed(&valid_chain, digest(250))
                .unwrap()
                .is_none(),
            "a valid prefix with the wrong trusted head is not recoverable"
        );

        let broken = ordinary_record(9, first.digest());
        let mut discontinuous = first.bytes().to_vec();
        discontinuous.extend_from_slice(broken.bytes());
        assert!(matches!(
            scan_journal_to_head_borrowed(&discontinuous, broken.digest()),
            Err(JournalDecodeError::ChainMismatch { offset }) if offset == first.bytes().len()
        ));
    }

    #[test]
    fn owned_and_borrowed_scans_reject_a_checksum_valid_revision_tamper() {
        let record = ordinary_record(0, Digest::ZERO);
        let mut bytes = record.bytes().to_vec();
        // Keep the envelope checksum valid while breaking the record's own
        // `base_revision + 1` relation.
        bytes[24..32].copy_from_slice(&2u64.to_le_bytes());
        let digest = Digest::new(Sha256::digest(&bytes[..bytes.len() - DIGEST_LEN]).into());
        let digest_offset = bytes.len() - DIGEST_LEN;
        bytes[digest_offset..].copy_from_slice(&digest.bytes());

        assert!(matches!(
            scan_journal(&bytes),
            Err(JournalDecodeError::ChainMismatch { offset: 0 })
        ));
        assert!(matches!(
            scan_journal_to_head_borrowed(&bytes, digest),
            Err(JournalDecodeError::ChainMismatch { offset: 0 })
        ));
    }

    #[test]
    fn borrowed_checkpoint_payload_validation_rejects_trailing_bytes() {
        let record = checkpoint_record(0, Digest::ZERO, b"state");
        let mut bytes = record.bytes().to_vec();
        let state_len_offset = FIXED_WITHOUT_DIGEST + 1 + DIGEST_LEN;
        bytes[state_len_offset..state_len_offset + 4].copy_from_slice(&4u32.to_le_bytes());
        let digest = Digest::new(Sha256::digest(&bytes[..bytes.len() - DIGEST_LEN]).into());
        let digest_offset = bytes.len() - DIGEST_LEN;
        bytes[digest_offset..].copy_from_slice(&digest.bytes());

        assert!(matches!(
            scan_journal_to_head_borrowed(&bytes, digest),
            Err(JournalDecodeError::Command(
                CommandDecodeError::TrailingBytes
            ))
        ));
    }

    #[test]
    fn borrowed_full_scan_keeps_a_near_limit_checkpoint_in_input() {
        let state = vec![0xa5; MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES];
        let record = checkpoint_record(0, Digest::ZERO, &state);
        let expected_head = record.digest();
        let input = record.bytes().to_vec();
        drop(record);

        let scan = scan_journal_borrowed(&input).unwrap();
        assert_eq!(scan.records().len(), 1);
        assert_eq!(scan.records()[0].digest(), expected_head);

        let view = scan.records()[0];
        let checkpoint = view
            .whole_state_checkpoint()
            .expect("near-limit checkpoint must remain a borrowed view");
        assert_eq!(checkpoint.state().len(), MAX_JOURNAL_CHECKPOINT_IMAGE_BYTES);
        assert_eq!(
            checkpoint.state().as_ptr(),
            input[checkpoint.state_range()].as_ptr()
        );
        assert_eq!(
            view.payload().as_ptr(),
            input[view.payload_range()].as_ptr()
        );
    }
}

#[cfg(test)]
mod read_at_source_tests {
    use alloc::{sync::Arc, vec, vec::Vec};

    use super::{
        recovery_source::{
            JournalRecoverySource, ReadAtCursor, RecoveryExpectation, RecoverySourceSnapshot,
            SliceRecoverySource,
        },
        *,
    };

    fn digest(value: u8) -> Digest {
        Digest::new([value; 32])
    }

    fn freshness() -> crate::Freshness {
        crate::Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        )
    }

    fn binding() -> RecoveryBinding {
        RecoveryBinding::new(
            RecoveryProfile::current(),
            WorldId::new(1).unwrap(),
            digest(9),
            RegistryInstance::new(1).unwrap(),
        )
        .unwrap()
    }

    fn ordinary_record(base_revision: u64, predecessor: Digest) -> JournalRecord {
        JournalRecord::build(
            base_revision,
            freshness(),
            binding(),
            digest(7),
            predecessor,
            CommandKind::CheckpointRecovery {
                boot: BootGeneration::new(2).unwrap(),
                journal: JournalGeneration::new(2).unwrap(),
                device: DeviceGeneration::new(1).unwrap(),
            },
        )
        .unwrap()
    }

    fn checkpoint_record(base_revision: u64, predecessor: Digest, state: &[u8]) -> JournalRecord {
        JournalRecord::build(
            base_revision,
            freshness(),
            binding(),
            digest(7),
            predecessor,
            CommandKind::WholeStateCheckpointV1 {
                state: Arc::from(state.to_vec().into_boxed_slice()),
                projection: digest(8),
            },
        )
        .unwrap()
    }

    fn expectation(record: &JournalRecord) -> RecoveryExpectation {
        RecoveryExpectation::new(binding(), freshness(), record.revision(), record.digest())
    }

    #[test]
    fn fixed_scratch_cursor_crosses_every_small_chunk_boundary() {
        let bytes: Vec<u8> = (0..96).collect();
        for scratch_len in [1, 7, 31, 511, 512, 4096] {
            let mut source = SliceRecoverySource::new(&bytes);
            let snapshot = source.begin_snapshot().unwrap();
            let mut scratch = vec![0; scratch_len];
            let mut cursor = ReadAtCursor::new(
                &mut source,
                snapshot.token(),
                snapshot.logical_len(),
                1,
                15,
                &mut scratch,
            )
            .unwrap();
            assert_eq!(cursor.position(), 1);
            assert_eq!(cursor.u16().unwrap(), u16::from_le_bytes([1, 2]));
            assert_eq!(cursor.u32().unwrap(), u32::from_le_bytes([3, 4, 5, 6]));
            assert_eq!(
                cursor.u64().unwrap(),
                u64::from_le_bytes([7, 8, 9, 10, 11, 12, 13, 14])
            );
            let mut streamed = Vec::new();
            cursor
                .stream_bytes(1, |chunk| streamed.extend_from_slice(chunk))
                .unwrap();
            assert_eq!(streamed, [15]);
            assert_eq!(cursor.remaining(), 0);
        }
    }

    #[test]
    fn anchored_inspection_is_chunk_invariant_and_keeps_only_layout() {
        let record = checkpoint_record(4, digest(6), b"read-at checkpoint state");
        let bytes = record.bytes();
        for scratch_len in [1, 7, 31, 511, 512, 4096] {
            let mut source = SliceRecoverySource::new(bytes);
            let mut scratch = vec![0; scratch_len];
            let inspection =
                inspect_journal_source_to_head(expectation(&record), &mut source, &mut scratch)
                    .unwrap()
                    .unwrap();
            assert_eq!(inspection.layout().accepted_len(), bytes.len());
            assert_eq!(inspection.layout().record_count(), 1);
            assert_eq!(
                inspection.accepted_prefix_digest(),
                Digest::new(Sha256::digest(bytes).into())
            );
            assert_eq!(inspection.repair(), None);
            let checkpoint = inspection.layout().leading_checkpoint().unwrap();
            assert_eq!(checkpoint.record_offset(), 0);
            assert_eq!(checkpoint.record_len(), bytes.len());
            assert_eq!(checkpoint.projection(), digest(8));
            assert_eq!(
                &bytes
                    [checkpoint.state_offset()..checkpoint.state_offset() + checkpoint.state_len()],
                b"read-at checkpoint state"
            );
        }
    }

    #[test]
    fn every_truncation_before_the_anchor_is_not_a_match() {
        let record = ordinary_record(0, Digest::ZERO);
        for end in 0..record.bytes().len() {
            let mut source = SliceRecoverySource::new(&record.bytes()[..end]);
            let mut scratch = [0u8; 7];
            assert_eq!(
                inspect_journal_source_to_head(expectation(&record), &mut source, &mut scratch,)
                    .unwrap(),
                None,
                "truncation at {end}"
            );
        }
    }

    #[test]
    fn corruption_before_anchor_fails_but_bytes_after_anchor_are_only_repair() {
        let record = ordinary_record(0, Digest::ZERO);
        let mut corrupt = record.bytes().to_vec();
        corrupt[FIXED_WITHOUT_DIGEST] ^= 0x40;
        let mut source = SliceRecoverySource::new(&corrupt);
        let mut scratch = [0u8; 31];
        assert!(matches!(
            inspect_journal_source_to_head(expectation(&record), &mut source, &mut scratch),
            Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::ChecksumMismatch { offset: 0 }
            ))
        ));

        let mut suffix = record.bytes().to_vec();
        suffix.extend_from_slice(b"arbitrary torn or corrupt unanchored bytes");
        let mut source = SliceRecoverySource::new(&suffix);
        let inspection =
            inspect_journal_source_to_head(expectation(&record), &mut source, &mut scratch)
                .unwrap()
                .unwrap();
        assert_eq!(
            inspection.repair(),
            Some(JournalRepair::UnanchoredSuffix {
                offset: record.bytes().len()
            })
        );
    }

    #[test]
    fn positioned_scanner_enforces_the_same_successor_chain_as_borrowed_scan() {
        let first = ordinary_record(0, Digest::ZERO);
        let second = ordinary_record(first.revision(), first.digest());
        let mut bytes = first.bytes().to_vec();
        bytes.extend_from_slice(second.bytes());
        let expected =
            RecoveryExpectation::new(binding(), freshness(), second.revision(), second.digest());
        let mut source = SliceRecoverySource::new(&bytes);
        let mut scratch = [0u8; 7];
        let read_at = inspect_journal_source_to_head(expected, &mut source, &mut scratch)
            .unwrap()
            .unwrap();
        let borrowed = scan_journal_to_head_borrowed(&bytes, second.digest())
            .unwrap()
            .unwrap();
        assert_eq!(read_at.layout().record_count(), borrowed.records().len());
        assert_eq!(read_at.layout().accepted_len(), bytes.len());

        let bad_second = ordinary_record(first.revision() + 1, first.digest());
        let mut broken = first.bytes().to_vec();
        broken.extend_from_slice(bad_second.bytes());
        let mut source = SliceRecoverySource::new(&broken);
        let bad_expected = RecoveryExpectation::new(
            binding(),
            freshness(),
            bad_second.revision(),
            bad_second.digest(),
        );
        assert!(matches!(
            inspect_journal_source_to_head(bad_expected, &mut source, &mut scratch),
            Err(AnchoredJournalInspectionError::Journal(
                JournalDecodeError::ChainMismatch { .. }
            ))
        ));
    }

    #[derive(Debug, Eq, PartialEq)]
    enum ChangingError {
        Changed,
        Range,
    }

    struct ChangingSource {
        bytes: Vec<u8>,
    }

    impl JournalRecoverySource for ChangingSource {
        type Error = ChangingError;
        type Snapshot = u64;

        fn begin_snapshot(
            &mut self,
        ) -> Result<RecoverySourceSnapshot<Self::Snapshot>, Self::Error> {
            Ok(RecoverySourceSnapshot::new(1, self.bytes.len() as u64))
        }

        fn read_exact_at(
            &mut self,
            snapshot: Self::Snapshot,
            offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if snapshot != 1 {
                return Err(ChangingError::Changed);
            }
            let start = usize::try_from(offset).map_err(|_| ChangingError::Range)?;
            let end = start
                .checked_add(output.len())
                .ok_or(ChangingError::Range)?;
            output.copy_from_slice(self.bytes.get(start..end).ok_or(ChangingError::Range)?);
            Ok(())
        }

        fn validate_snapshot(&mut self, _snapshot: Self::Snapshot) -> Result<(), Self::Error> {
            Err(ChangingError::Changed)
        }
    }

    #[test]
    fn changed_snapshot_fails_closed_after_a_matching_scan() {
        let record = ordinary_record(0, Digest::ZERO);
        let mut source = ChangingSource {
            bytes: record.bytes().to_vec(),
        };
        let mut scratch = [0u8; 31];
        assert_eq!(
            inspect_journal_source_to_head(expectation(&record), &mut source, &mut scratch),
            Err(AnchoredJournalInspectionError::Source(
                ChangingError::Changed
            ))
        );
    }
}
