// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec::Vec};

use sha2::{Digest as _, Sha256};

use crate::{
    BootGeneration, CSER_CORE_API_PROFILE_VERSION, DeviceGeneration, Digest, JournalGeneration,
    RecoveryBinding, RecoveryProfile, RegistryInstance, WorldId,
    engine::{CommandDecodeError, CommandKind, MAX_COMMAND_PAYLOAD_BYTES},
};

/// Magic prefix of every CSER journal record.
pub const JOURNAL_MAGIC: [u8; 8] = *b"CSERJ10\0";
/// Frozen journal schema for the current CSER Core semantic API profile.
pub const JOURNAL_SCHEMA_VERSION: u16 = 10;
/// Semantic core API profile explicitly bound in every schema-10 envelope.
pub const JOURNAL_CORE_API_PROFILE: u16 = CSER_CORE_API_PROFILE_VERSION;

/// Magic prefix of a portable exact-replay checkpoint envelope.
///
/// This is deliberately distinct from a journal record. A checkpoint carries
/// a canonical *image* of the exact journal prefix it replaces; it is not a
/// lossy serialization of the private engine state.
pub const JOURNAL_CHECKPOINT_MAGIC: [u8; 8] = *b"CSERCP3\0";
/// Version of [`JournalCheckpoint`] envelopes.
pub const JOURNAL_CHECKPOINT_VERSION: u16 = 3;
const PREVIOUS_CHECKPOINT_MAGIC: [u8; 8] = *b"CSERCP2\0";
const LEGACY_CHECKPOINT_MAGIC: [u8; 8] = *b"CSERCP1\0";

const PRE_HANDOFF_RESOLUTION_JOURNAL_MAGIC: [u8; 8] = *b"CSERJR7\0";
const PRE_HANDOFF_RESOLUTION_JOURNAL_SCHEMA_VERSION: u16 = 7;
const PREVIOUS_JOURNAL_MAGIC: [u8; 8] = *b"CSERJR9\0";
const PREVIOUS_JOURNAL_SCHEMA_VERSION: u16 = 9;
const PREVIOUS_PREVIOUS_JOURNAL_MAGIC: [u8; 8] = *b"CSERJR8\0";
const PREVIOUS_PREVIOUS_JOURNAL_SCHEMA_VERSION: u16 = 8;
const PROFILE_ONE_JOURNAL_MAGIC: [u8; 8] = *b"CSERJR5\0";
const PROFILE_ONE_JOURNAL_SCHEMA_VERSION: u16 = 5;
const LEGACY_JOURNAL_MAGIC: [u8; 8] = *b"CSERJR4\0";
const LEGACY_JOURNAL_SCHEMA_VERSION: u16 = 4;

// prefix + revisions + profile + world + catalog + registry +
// freshness axes + base projection + predecessor + payload length.
const FIXED_WITHOUT_DIGEST: usize = 180;
const DIGEST_LEN: usize = 32;
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
            return Err(JournalCheckpointDecodeError::UnsupportedVersion { version: 2 });
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
    /// The anchor is consumed by [`crate::Engine::recover`], which reserves a
    /// newer freshness epoch, fences operations, and quarantines device claims.
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
        // Rebuild the pre-recovery image before advancing freshness. This
        // binds the stored projection to actual replayed state; the following
        // normal recovery deliberately changes that projection by installing
        // a recovery target and device quarantine.
        crate::Engine::validate_journal_checkpoint(catalog.clone(), limits, self)?;
        crate::Engine::recover(catalog, limits, anchor, self.image())
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
    scan_journal_inner(bytes, None).map(|(scan, _)| scan)
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
        b"CSERJR9\0" => Some(PREVIOUS_JOURNAL_SCHEMA_VERSION),
        b"CSERJR8\0" => Some(PREVIOUS_PREVIOUS_JOURNAL_SCHEMA_VERSION),
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

fn scan_journal_inner(
    bytes: &[u8],
    expected_head: Option<Digest>,
) -> Result<(JournalScan, bool), JournalDecodeError> {
    let mut records = Vec::new();
    let mut offset = 0usize;
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

        records.push(JournalRecord {
            base_revision: read_u64(record_bytes, 16),
            revision: read_u64(record_bytes, 24),
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
    fn decode_identifies_the_predecessor_checkpoint_before_vnext_length_checks() {
        let mut bytes = vec![0u8; 196];
        bytes[..8].copy_from_slice(&PREVIOUS_CHECKPOINT_MAGIC);
        assert_eq!(
            JournalCheckpoint::decode(&bytes),
            Err(JournalCheckpointDecodeError::UnsupportedVersion { version: 2 })
        );
    }

    #[test]
    fn decode_identifies_schema_nine_journal_before_vnext_length_checks() {
        let mut bytes = vec![0u8; 16];
        bytes[..8].copy_from_slice(&PREVIOUS_JOURNAL_MAGIC);
        assert!(matches!(
            scan_journal(&bytes),
            Err(JournalDecodeError::UnsupportedVersion { version: 9 })
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
