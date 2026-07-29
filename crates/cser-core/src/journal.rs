// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;

use sha2::{Digest as _, Sha256};

use crate::{
    BootGeneration, DeviceGeneration, Digest, JournalGeneration, RegistryInstance,
    engine::{CommandDecodeError, CommandKind},
};

/// Magic prefix of every CSER journal record.
pub const JOURNAL_MAGIC: [u8; 8] = *b"CSERJR5\0";
/// Frozen journal schema for CSER core semantic API profile 1.
pub const JOURNAL_SCHEMA_VERSION: u16 = 5;

const PREVIOUS_JOURNAL_MAGIC: [u8; 8] = *b"CSERJR4\0";
const PREVIOUS_JOURNAL_SCHEMA_VERSION: u16 = 4;

const FIXED_WITHOUT_DIGEST: usize = 140;
const DIGEST_LEN: usize = 32;
const MIN_RECORD_LEN: usize = FIXED_WITHOUT_DIGEST + DIGEST_LEN;

/// One validated, hash-chained CSER journal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRecord {
    base_revision: u64,
    revision: u64,
    boot: BootGeneration,
    registry: RegistryInstance,
    binding: u64,
    journal: JournalGeneration,
    device: DeviceGeneration,
    catalog_digest: Digest,
    predecessor: Digest,
    command: CommandKind,
    digest: Digest,
    bytes: Vec<u8>,
}

impl JournalRecord {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build(
        base_revision: u64,
        boot: BootGeneration,
        registry: RegistryInstance,
        binding: u64,
        journal: JournalGeneration,
        device: DeviceGeneration,
        catalog_digest: Digest,
        predecessor: Digest,
        command: CommandKind,
    ) -> Result<Self, JournalDecodeError> {
        let revision = base_revision
            .checked_add(1)
            .ok_or(JournalDecodeError::RevisionOverflow)?;
        let payload = command.encode_payload();
        let total_len = MIN_RECORD_LEN
            .checked_add(payload.len())
            .ok_or(JournalDecodeError::LengthOverflow)?;
        let total_len_u32 =
            u32::try_from(total_len).map_err(|_| JournalDecodeError::LengthOverflow)?;
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| JournalDecodeError::LengthOverflow)?;

        let mut bytes = Vec::with_capacity(total_len);
        bytes.extend_from_slice(&JOURNAL_MAGIC);
        bytes.extend_from_slice(&JOURNAL_SCHEMA_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&total_len_u32.to_le_bytes());
        bytes.extend_from_slice(&base_revision.to_le_bytes());
        bytes.extend_from_slice(&revision.to_le_bytes());
        bytes.extend_from_slice(&boot.get().to_le_bytes());
        bytes.extend_from_slice(&registry.get().to_le_bytes());
        bytes.extend_from_slice(&binding.to_le_bytes());
        bytes.extend_from_slice(&journal.get().to_le_bytes());
        bytes.extend_from_slice(&device.get().to_le_bytes());
        bytes.extend_from_slice(&catalog_digest.bytes());
        bytes.extend_from_slice(&predecessor.bytes());
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&payload);
        debug_assert_eq!(bytes.len(), total_len - DIGEST_LEN);

        let digest = Digest::new(Sha256::digest(&bytes).into());
        bytes.extend_from_slice(&digest.bytes());

        Ok(Self {
            base_revision,
            revision,
            boot,
            registry,
            binding,
            journal,
            device,
            catalog_digest,
            predecessor,
            command,
            digest,
            bytes,
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

    /// Returns the exact principal-binding generation at preparation.
    pub const fn binding(&self) -> u64 {
        self.binding
    }

    /// Returns the journal generation.
    pub const fn journal(&self) -> JournalGeneration {
        self.journal
    }

    /// Returns the device generation.
    pub const fn device(&self) -> DeviceGeneration {
        self.device
    }

    /// Returns the bound domain-catalog digest.
    pub const fn catalog_digest(&self) -> Digest {
        self.catalog_digest
    }

    /// Returns the predecessor record digest.
    pub const fn predecessor(&self) -> Digest {
        self.predecessor
    }

    pub(crate) const fn command(&self) -> &CommandKind {
        &self.command
    }

    /// Returns this record's digest.
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// Returns the exact durable bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
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
    /// Reserved envelope bits were non-zero.
    ReservedBits,
    /// A declared record length is structurally invalid.
    InvalidLength,
    /// A length cannot be represented by the journal format.
    LengthOverflow,
    /// A revision increment overflowed.
    RevisionOverflow,
    /// A non-zero stable identity decoded as zero.
    ZeroIdentity,
    /// The payload does not encode a known command.
    Command(CommandDecodeError),
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
/// or checksum-invalid complete record fails closed.
pub fn scan_journal(bytes: &[u8]) -> Result<JournalScan, JournalDecodeError> {
    scan_journal_inner(bytes, None).map(|(scan, _)| scan)
}

/// Validates records only through one exact externally anchored head.
///
/// Bytes after the selected record are deliberately not decoded. They may be
/// a complete append whose freshness anchor never committed, a torn append, or
/// arbitrary failed-write residue. The returned suffix offset must be repaired
/// before the recovered engine can accept another transition.
///
/// Returns `None` when the exact head does not occur in the validated prefix.
pub fn scan_journal_to_head(
    bytes: &[u8],
    expected_head: Digest,
) -> Result<Option<JournalScan>, JournalDecodeError> {
    let (scan, found) = scan_journal_inner(bytes, Some(expected_head))?;
    Ok(found.then_some(scan))
}

fn scan_journal_inner(
    bytes: &[u8],
    expected_head: Option<Digest>,
) -> Result<(JournalScan, bool), JournalDecodeError> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
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
        if remaining[..8] == PREVIOUS_JOURNAL_MAGIC {
            return Err(JournalDecodeError::UnsupportedVersion {
                version: PREVIOUS_JOURNAL_SCHEMA_VERSION,
            });
        }
        if remaining[..8] != JOURNAL_MAGIC {
            return Err(JournalDecodeError::BadMagic { offset });
        }
        let version = read_u16(remaining, 8);
        if version != JOURNAL_SCHEMA_VERSION {
            return Err(JournalDecodeError::UnsupportedVersion { version });
        }
        if read_u16(remaining, 10) != 0 {
            return Err(JournalDecodeError::ReservedBits);
        }
        let total_len = read_u32(remaining, 12) as usize;
        if total_len < MIN_RECORD_LEN {
            return Err(JournalDecodeError::InvalidLength);
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
        let payload_len = read_u32(record_bytes, 136) as usize;
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

        let boot = BootGeneration::new(read_u64(record_bytes, 32))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let registry = RegistryInstance::new(read_u64(record_bytes, 40))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let binding = read_u64(record_bytes, 48);
        if binding == 0 {
            return Err(JournalDecodeError::ZeroIdentity);
        }
        let journal = JournalGeneration::new(read_u64(record_bytes, 56))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let device = DeviceGeneration::new(read_u64(record_bytes, 64))
            .map_err(|_| JournalDecodeError::ZeroIdentity)?;
        let catalog_digest = Digest::new(
            record_bytes[72..104]
                .try_into()
                .map_err(|_| JournalDecodeError::InvalidLength)?,
        );
        let predecessor = Digest::new(
            record_bytes[104..136]
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
            binding,
            journal,
            device,
            catalog_digest,
            predecessor,
            command,
            digest: expected,
            bytes: record_bytes.to_vec(),
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
