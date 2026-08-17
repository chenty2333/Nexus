// SPDX-License-Identifier: MPL-2.0

//! Standard-library persistence helpers for host adapters and recovery tests.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use crate::{
    Digest, JournalRecord, JournalRepair,
    journal::{
        JOURNAL_RECORD_HEADER_LEN, MAX_JOURNAL_SCAN_BYTES, MAX_JOURNAL_SCAN_RECORDS,
        journal_record_total_len, recognized_legacy_journal_version,
    },
    scan_journal,
};

mod persistence;

pub use persistence::{HostAnchorError, HostAnchorFailpoint, HostFileTrustedAnchor};

/// Single-writer file journal which validates its durable head before append.
///
/// `FileJournal` is a host adapter and test fixture, not an anti-rollback
/// freshness provider. It holds an OS-backed exclusive advisory lock for its
/// entire lifetime, but the embedding process must still supply an external
/// trusted recovery anchor and prevent non-cooperating writers from bypassing
/// that lock.
#[derive(Debug)]
pub struct FileJournal {
    path: PathBuf,
    file: File,
    durable_len: u64,
    revision: u64,
    head: Digest,
    journal_repair: Option<JournalRepair>,
    recovery_required: bool,
}

impl FileJournal {
    /// Opens or creates a journal and validates every complete record.
    ///
    /// A torn tail is not silently discarded. Call
    /// [`Self::repair_to_anchored_prefix`] with the prefix coordinates
    /// accepted by recovery before any further append.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        file.try_lock()?;

        if file.metadata()?.len() == 0 {
            file.sync_all()?;
            sync_parent_directory(&path)?;
        }

        let bytes = read_all_file(&mut file)?;
        let scan = scan_journal(&bytes).map_err(invalid_journal)?;
        let (revision, head) = scan.records().last().map_or((0, Digest::ZERO), |record| {
            (record.revision(), record.digest())
        });
        Ok(Self {
            path,
            file,
            durable_len: u64::try_from(bytes.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "journal length exceeds u64")
            })?,
            revision,
            head,
            journal_repair: scan
                .torn_tail()
                .map(|offset| JournalRepair::TornTail { offset }),
            recovery_required: false,
        })
    }

    /// Opens a journal at the exact prefix committed by a trusted anchor.
    ///
    /// Unlike [`Self::open`], this recovery path may accept complete, torn, or
    /// corrupt bytes after the exact anchored head. It never interprets that
    /// suffix as authoritative state, and it refuses all appends until
    /// [`Self::repair_to_anchored_prefix`] durably truncates it.
    pub fn open_anchored(
        path: impl AsRef<Path>,
        accepted_revision: u64,
        accepted_head: Digest,
    ) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .create(false)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        file.try_lock()?;
        let durable_len = file.metadata()?.len();
        if accepted_revision == 0 || accepted_head.is_zero() {
            if accepted_revision != 0 || !accepted_head.is_zero() {
                return Err(anchor_not_found());
            }
            reject_genesis_legacy_prefix(&mut file, durable_len)?;
            let durable_len = file.metadata()?.len();
            return Ok(Self {
                path,
                file,
                durable_len,
                revision: 0,
                head: Digest::ZERO,
                journal_repair: (durable_len != 0)
                    .then_some(JournalRepair::UnanchoredSuffix { offset: 0 }),
                recovery_required: false,
            });
        }
        file.seek(SeekFrom::Start(0))?;
        let accepted_len = read_anchored_prefix(&mut file, accepted_revision, accepted_head)?;
        let durable_len = file.metadata()?.len();
        let accepted_len_u64 = u64::try_from(accepted_len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "accepted journal length exceeds u64",
            )
        })?;
        if accepted_len_u64 > durable_len {
            return Err(anchor_not_found());
        }
        let journal_repair =
            (durable_len > accepted_len_u64).then_some(JournalRepair::UnanchoredSuffix {
                offset: accepted_len,
            });
        Ok(Self {
            path,
            file,
            durable_len,
            revision: accepted_revision,
            head: accepted_head,
            journal_repair,
            recovery_required: false,
        })
    }

    /// Appends one complete record and executes the durability barrier.
    ///
    /// The current file length and the record's predecessor coordinates must
    /// still match the head validated by this handle. An error returned after
    /// writing may be ambiguous; callers must treat it as potentially durable
    /// and recover before attempting another semantic append.
    pub fn append(&mut self, record: &JournalRecord) -> io::Result<()> {
        if self.recovery_required {
            return Err(recovery_required());
        }
        if self.journal_repair.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal has an unrepaired suffix",
            ));
        }
        let observed_len = self.file.metadata()?.len();
        if observed_len != self.durable_len
            || record.base_revision() != self.revision
            || record.predecessor() != self.head
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal head changed or append record is stale",
            ));
        }
        self.file.seek(SeekFrom::End(0))?;
        self.recovery_required = true;
        self.file.write_all(record.bytes())?;
        self.file.sync_all()?;
        self.durable_len = self
            .durable_len
            .checked_add(u64::try_from(record.bytes().len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "record length exceeds u64")
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "journal length overflow"))?;
        self.revision = record.revision();
        self.head = record.digest();
        self.journal_repair = None;
        self.recovery_required = false;
        Ok(())
    }

    /// Truncates only the incomplete tail following an externally accepted
    /// journal prefix.
    ///
    /// `accepted_revision` and `accepted_head` must identify the final complete
    /// record immediately before `accepted_len`. This method rejects complete
    /// corruption and refuses to truncate a different prefix.
    pub fn repair_to_anchored_prefix(
        &mut self,
        accepted_len: usize,
        accepted_revision: u64,
        accepted_head: Digest,
    ) -> io::Result<()> {
        if self.recovery_required {
            return Err(recovery_required());
        }
        let observed_len = self.file.metadata()?.len();
        if observed_len != self.durable_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal length changed after open",
            ));
        }
        let repair = self.journal_repair.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal has no anchored suffix to repair",
            )
        })?;
        if repair.offset() != accepted_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "accepted offset is not the validated repair boundary",
            ));
        }
        let (revision, head) = if accepted_revision == 0 && accepted_head.is_zero() {
            (0, Digest::ZERO)
        } else {
            self.file.seek(SeekFrom::Start(0))?;
            let validated_len =
                read_anchored_prefix(&mut self.file, accepted_revision, accepted_head)?;
            if validated_len != accepted_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "accepted offset is not the validated repair boundary",
                ));
            }
            (accepted_revision, accepted_head)
        };
        if revision != accepted_revision || head != accepted_head {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "accepted journal coordinates do not match the validated prefix",
            ));
        }

        let accepted_len = u64::try_from(accepted_len).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "accepted offset exceeds u64")
        })?;
        self.recovery_required = true;
        self.file.set_len(accepted_len)?;
        self.file.sync_all()?;
        sync_parent_directory(&self.path)?;
        self.file.seek(SeekFrom::Start(accepted_len))?;
        self.durable_len = accepted_len;
        self.revision = revision;
        self.head = head;
        self.journal_repair = None;
        self.recovery_required = false;
        Ok(())
    }

    /// Returns the backing path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the complete current byte stream through the locked descriptor.
    pub fn read_all(&mut self) -> io::Result<Vec<u8>> {
        read_all_file(&mut self.file)
    }

    /// Returns the complete-record revision validated by this handle.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the complete-record head validated by this handle.
    pub const fn head(&self) -> Digest {
        self.head
    }

    /// Returns the incomplete-tail boundary observed while opening.
    pub const fn torn_tail(&self) -> Option<usize> {
        match self.journal_repair {
            Some(JournalRepair::TornTail { offset }) => Some(offset),
            Some(JournalRepair::UnanchoredSuffix { .. }) | None => None,
        }
    }

    /// Returns the exact repair selected by anchored recovery.
    pub const fn journal_repair(&self) -> Option<JournalRepair> {
        self.journal_repair
    }

    /// Returns whether an append or truncate failure made this handle unsafe
    /// for further mutation. Drop and reopen it before continuing recovery.
    pub const fn recovery_required(&self) -> bool {
        self.recovery_required
    }
}

impl Drop for FileJournal {
    fn drop(&mut self) {
        let _ = File::unlock(&self.file);
    }
}

impl crate::DurableJournalBackend for FileJournal {
    type Error = io::Error;

    fn append_and_sync(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.append(record)
    }
}

/// Reads an entire journal file.
pub fn read_all(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_all_file(file: &mut File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.seek(SeekFrom::Start(0))?;
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Reads and validates only the complete prefix ending at `expected_head`.
///
/// The fixed envelope header is admitted before allocating one bounded record
/// body, and the reader is never advanced beyond the accepted record. The
/// returned length is bounded by the same portable scan limits as
/// [`scan_journal`].
fn read_anchored_prefix<R: Read>(
    reader: &mut R,
    accepted_revision: u64,
    accepted_head: Digest,
) -> io::Result<usize> {
    let mut prefix_len = 0usize;
    let mut record_count = 0usize;
    let mut previous = None;

    loop {
        if record_count >= MAX_JOURNAL_SCAN_RECORDS {
            return Err(invalid_journal(
                crate::JournalDecodeError::RecordCountExceeded {
                    limit: MAX_JOURNAL_SCAN_RECORDS,
                },
            ));
        }

        let mut header = [0u8; JOURNAL_RECORD_HEADER_LEN];
        match reader.read_exact(&mut header[..8]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(anchor_not_found());
            }
            Err(error) => return Err(error),
        }
        if let Some(version) = recognized_legacy_journal_version(&header[..8]) {
            return Err(invalid_journal(
                crate::JournalDecodeError::UnsupportedVersion { version },
            ));
        }
        match reader.read_exact(&mut header[8..]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(anchor_not_found());
            }
            Err(error) => return Err(error),
        }
        let total_len = journal_record_total_len(&header).map_err(invalid_journal)?;
        if total_len > MAX_JOURNAL_SCAN_BYTES || prefix_len > MAX_JOURNAL_SCAN_BYTES - total_len {
            return Err(invalid_journal(crate::JournalDecodeError::InputTooLarge {
                limit: MAX_JOURNAL_SCAN_BYTES,
            }));
        }

        let mut record = Vec::new();
        record
            .try_reserve_exact(total_len)
            .map_err(|_| journal_allocation_failed())?;
        record.resize(total_len, 0);
        record[..JOURNAL_RECORD_HEADER_LEN].copy_from_slice(&header);
        match reader.read_exact(&mut record[JOURNAL_RECORD_HEADER_LEN..]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(anchor_not_found());
            }
            Err(error) => return Err(error),
        }
        let scan = scan_journal(&record).map_err(invalid_journal)?;
        let current = scan.records().first().ok_or_else(anchor_not_found)?;
        if let Some((previous_revision, previous_head)) = previous {
            if current.base_revision() != previous_revision
                || current.predecessor() != previous_head
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "journal record chain is discontinuous",
                ));
            }
        }
        prefix_len = prefix_len
            .checked_add(total_len)
            .ok_or_else(|| invalid_journal(crate::JournalDecodeError::LengthOverflow))?;
        record_count += 1;

        if current.digest() == accepted_head {
            if current.revision() != accepted_revision {
                return Err(anchor_not_found());
            }
            return Ok(prefix_len);
        }
        previous = Some((current.revision(), current.digest()));
    }
}

fn journal_allocation_failed() -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        "journal record allocation failed during anchored recovery",
    )
}

/// Rejects a recognized predecessor schema using only its fixed magic prefix.
fn reject_genesis_legacy_prefix(file: &mut File, durable_len: u64) -> io::Result<()> {
    if durable_len < JOURNAL_RECORD_HEADER_LEN as u64 / 2 {
        return Ok(());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut prefix = [0u8; JOURNAL_RECORD_HEADER_LEN];
    file.read_exact(&mut prefix[..JOURNAL_RECORD_HEADER_LEN / 2])?;
    if let Some(version) = recognized_legacy_journal_version(&prefix) {
        return Err(invalid_journal(
            crate::JournalDecodeError::UnsupportedVersion { version },
        ));
    }
    Ok(())
}

fn recovery_required() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "journal mutation failed ambiguously; drop and reopen before continuing",
    )
}

fn anchor_not_found() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "trusted journal anchor does not name a validated prefix",
    )
}

fn invalid_journal(error: crate::JournalDecodeError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid CSER journal: {error:?}"),
    )
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Cursor, Read},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::journal::{MAX_JOURNAL_SCAN_BYTES, MAX_JOURNAL_SCAN_RECORDS};
    use crate::{
        BootGeneration, DeviceGeneration, Digest, JournalDecodeError, JournalGeneration,
        JournalRecord, JournalRepair, RegistryInstance, engine::CommandKind, scan_journal,
        scan_journal_to_head,
    };

    use super::FileJournal;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempJournal {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TempJournal {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "nexus-cser-journal-{label}-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&directory).expect("create isolated journal test directory");
            let path = directory.join("journal.bin");
            Self { directory, path }
        }
    }

    impl Drop for TempJournal {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn digest(value: u8) -> Digest {
        Digest::new([value; 32])
    }

    struct CountingReader {
        inner: Cursor<Vec<u8>>,
        bytes_read: usize,
    }

    impl CountingReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                inner: Cursor::new(bytes),
                bytes_read: 0,
            }
        }
    }

    impl Read for CountingReader {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let count = self.inner.read(bytes)?;
            self.bytes_read += count;
            Ok(count)
        }
    }

    fn record(base_revision: u64, predecessor: Digest) -> JournalRecord {
        let freshness = crate::Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        );
        let binding = crate::RecoveryBinding::new(
            crate::RecoveryProfile::current(),
            crate::WorldId::new(1).unwrap(),
            digest(9),
            RegistryInstance::new(1).unwrap(),
        )
        .unwrap();
        JournalRecord::build(
            base_revision,
            freshness,
            binding,
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

    #[test]
    fn profile_one_v5_schema_is_rejected_explicitly() {
        let mut bytes = record(0, Digest::ZERO).bytes().to_vec();
        bytes[..8].copy_from_slice(b"CSERJR5\0");
        bytes[8..10].copy_from_slice(&5u16.to_le_bytes());

        assert!(matches!(
            scan_journal(&bytes),
            Err(JournalDecodeError::UnsupportedVersion { version: 5 })
        ));
    }

    #[test]
    fn legacy_v4_schema_is_rejected_explicitly() {
        let mut bytes = record(0, Digest::ZERO).bytes().to_vec();
        bytes[..8].copy_from_slice(b"CSERJR4\0");
        bytes[8..10].copy_from_slice(&4u16.to_le_bytes());

        assert!(matches!(
            scan_journal(&bytes),
            Err(JournalDecodeError::UnsupportedVersion { version: 4 })
        ));
    }

    #[test]
    fn second_writer_open_is_rejected_until_the_first_handle_drops() {
        let temp = TempJournal::new("single-writer");
        let first = FileJournal::open(&temp.path).unwrap();

        let error = FileJournal::open(&temp.path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);

        drop(first);
        let reopened = FileJournal::open(&temp.path).unwrap();
        assert_eq!(reopened.revision(), 0);
        assert_eq!(reopened.head(), Digest::ZERO);
    }

    #[test]
    fn exact_torn_tail_repair_is_durable_and_reopenable() {
        let temp = TempJournal::new("repair");
        let first = record(0, Digest::ZERO);
        let second = record(first.revision(), first.digest());
        let accepted_len = first.bytes().len();
        let mut torn = first.bytes().to_vec();
        torn.extend_from_slice(&second.bytes()[..second.bytes().len() / 2]);
        std::fs::write(&temp.path, &torn).unwrap();

        let mut journal = FileJournal::open(&temp.path).unwrap();
        assert_eq!(journal.torn_tail(), Some(accepted_len));
        assert!(journal.append(&second).is_err());
        assert!(
            journal
                .repair_to_anchored_prefix(accepted_len, first.revision(), digest(250))
                .is_err()
        );
        journal
            .repair_to_anchored_prefix(accepted_len, first.revision(), first.digest())
            .unwrap();
        assert_eq!(journal.read_all().unwrap(), first.bytes());
        drop(journal);

        let mut reopened = FileJournal::open(&temp.path).unwrap();
        assert_eq!(reopened.torn_tail(), None);
        assert_eq!(reopened.revision(), first.revision());
        assert_eq!(reopened.head(), first.digest());
        reopened.append(&second).unwrap();
        drop(reopened);

        let mut reopened = FileJournal::open(&temp.path).unwrap();
        let scan = scan_journal(&reopened.read_all().unwrap()).unwrap();
        assert_eq!(scan.records().len(), 2);
        assert_eq!(scan.records()[1].digest(), second.digest());
    }

    #[test]
    fn anchored_open_repairs_a_complete_or_corrupt_uncommitted_suffix() {
        for corrupt in [false, true] {
            let label = if corrupt {
                "corrupt-unanchored"
            } else {
                "complete-unanchored"
            };
            let temp = TempJournal::new(label);
            let first = record(0, Digest::ZERO);
            let second = record(first.revision(), first.digest());
            let accepted_len = first.bytes().len();
            let mut bytes = first.bytes().to_vec();
            bytes.extend_from_slice(second.bytes());
            if corrupt {
                bytes[accepted_len + 24] ^= 0x40;
            }
            std::fs::write(&temp.path, &bytes).unwrap();
            if corrupt {
                assert!(FileJournal::open(&temp.path).is_err());
            }

            let mut journal =
                FileJournal::open_anchored(&temp.path, first.revision(), first.digest()).unwrap();
            assert_eq!(
                journal.journal_repair(),
                Some(JournalRepair::UnanchoredSuffix {
                    offset: accepted_len
                })
            );
            assert!(journal.append(&second).is_err());
            assert!(
                journal
                    .repair_to_anchored_prefix(accepted_len + 1, first.revision(), first.digest())
                    .is_err()
            );
            journal
                .repair_to_anchored_prefix(accepted_len, first.revision(), first.digest())
                .unwrap();
            assert_eq!(journal.read_all().unwrap(), first.bytes());
            drop(journal);

            let mut reopened = FileJournal::open(&temp.path).unwrap();
            reopened.append(&second).unwrap();
            assert_eq!(reopened.revision(), second.revision());
            assert_eq!(reopened.head(), second.digest());
        }
    }

    #[test]
    fn anchored_open_does_not_read_or_validate_a_large_unanchored_suffix() {
        let temp = TempJournal::new("large-unanchored-suffix");
        let first = record(0, Digest::ZERO);
        let suffix = vec![0xa5; MAX_JOURNAL_SCAN_BYTES + 1];
        let mut bytes = first.bytes().to_vec();
        bytes.extend_from_slice(&suffix);
        std::fs::write(&temp.path, &bytes).unwrap();

        let mut journal = FileJournal::open_anchored(&temp.path, first.revision(), first.digest())
            .expect("trusted prefix is independent of suffix contents");
        assert_eq!(
            journal.journal_repair(),
            Some(JournalRepair::UnanchoredSuffix {
                offset: first.bytes().len()
            })
        );
        assert!(
            journal
                .append(&record(first.revision(), first.digest()))
                .is_err()
        );
        journal
            .repair_to_anchored_prefix(first.bytes().len(), first.revision(), first.digest())
            .unwrap();
        assert_eq!(journal.read_all().unwrap(), first.bytes());
    }

    #[test]
    fn anchored_prefix_reader_stops_at_the_trusted_record() {
        let first = record(0, Digest::ZERO);
        let second = record(first.revision(), first.digest());
        let mut bytes = first.bytes().to_vec();
        bytes.extend_from_slice(second.bytes());
        bytes.extend_from_slice(&[0xff; 1024 * 1024]);
        let mut reader = CountingReader::new(bytes);

        let accepted_len =
            super::read_anchored_prefix(&mut reader, first.revision(), first.digest()).unwrap();
        assert_eq!(accepted_len, first.bytes().len());
        assert_eq!(reader.bytes_read, first.bytes().len());
    }

    #[test]
    fn anchored_prefix_rejects_a_discontinuous_record_chain() {
        let temp = TempJournal::new("discontinuous-chain");
        let first = record(0, Digest::ZERO);
        let second = record(first.revision() + 1, first.digest());
        let mut bytes = first.bytes().to_vec();
        bytes.extend_from_slice(second.bytes());
        std::fs::write(&temp.path, &bytes).unwrap();

        let error = FileJournal::open_anchored(&temp.path, second.revision(), second.digest())
            .expect_err("anchored prefix must be one contiguous chain");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "journal record chain is discontinuous");
    }

    #[test]
    fn scan_rejects_a_declared_record_larger_than_the_portable_record_budget() {
        let mut bytes = record(0, Digest::ZERO).bytes().to_vec();
        bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());

        assert!(matches!(
            scan_journal(&bytes),
            Err(JournalDecodeError::InvalidLength)
        ));
    }

    #[test]
    fn scan_rejects_too_many_minimal_valid_records_before_materializing_more() {
        let one = record(0, Digest::ZERO);
        let bytes = one.bytes().repeat(MAX_JOURNAL_SCAN_RECORDS + 1);

        assert!(matches!(
            scan_journal(&bytes),
            Err(JournalDecodeError::RecordCountExceeded {
                limit: MAX_JOURNAL_SCAN_RECORDS
            })
        ));
    }

    #[test]
    fn scan_to_head_stops_before_a_suffix_over_the_full_scan_budget() {
        let first = record(0, Digest::ZERO);
        let mut bytes = first.bytes().to_vec();
        bytes.resize(MAX_JOURNAL_SCAN_BYTES + 1, 0xa5);

        let scan = scan_journal_to_head(&bytes, first.digest())
            .unwrap()
            .expect("anchor occurs before oversized suffix");
        assert_eq!(scan.records().len(), 1);
        assert_eq!(scan.records()[0].digest(), first.digest());
        assert_eq!(scan.unanchored_suffix(), Some(first.bytes().len()));
    }

    #[test]
    fn anchored_open_can_repair_an_uncommitted_first_append_to_genesis() {
        let temp = TempJournal::new("genesis-unanchored");
        let first = record(0, Digest::ZERO);
        std::fs::write(&temp.path, first.bytes()).unwrap();

        let mut journal = FileJournal::open_anchored(&temp.path, 0, Digest::ZERO).unwrap();
        assert_eq!(
            journal.journal_repair(),
            Some(JournalRepair::UnanchoredSuffix { offset: 0 })
        );
        journal
            .repair_to_anchored_prefix(0, 0, Digest::ZERO)
            .unwrap();
        drop(journal);

        let reopened = FileJournal::open(&temp.path).unwrap();
        assert_eq!(reopened.revision(), 0);
        assert_eq!(reopened.head(), Digest::ZERO);
    }

    #[test]
    fn anchored_open_rejects_profile_one_before_repair_without_reclassifying_residue() {
        for (label, suffix) in [
            ("profile-one-prefix", &[][..]),
            (
                "profile-one-arbitrary-suffix",
                &b"\xffroots-and-timestamps\x00"[..],
            ),
        ] {
            let temp = TempJournal::new(label);
            let mut bytes = Vec::from(*b"CSERJR5\0");
            bytes.extend_from_slice(suffix);
            std::fs::write(&temp.path, &bytes).unwrap();

            let error =
                FileJournal::open_anchored(&temp.path, 0, Digest::ZERO).expect_err("reject v5");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                "invalid CSER journal: UnsupportedVersion { version: 5 }"
            );
            assert_eq!(std::fs::read(&temp.path).unwrap(), bytes);
        }

        let temp = TempJournal::new("profile-one-non-genesis-anchor");
        let bytes = Vec::from(*b"CSERJR5\0");
        std::fs::write(&temp.path, &bytes).unwrap();
        let error = FileJournal::open_anchored(&temp.path, 1, digest(77))
            .expect_err("reject v5 before searching a non-genesis anchor");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "invalid CSER journal: UnsupportedVersion { version: 5 }"
        );
        assert_eq!(std::fs::read(&temp.path).unwrap(), bytes);

        let temp = TempJournal::new("genesis-arbitrary-residue");
        let residue = b"arbitrary failed-write residue";
        std::fs::write(&temp.path, residue).unwrap();
        let mut journal = FileJournal::open_anchored(&temp.path, 0, Digest::ZERO).unwrap();
        assert_eq!(
            journal.journal_repair(),
            Some(JournalRepair::UnanchoredSuffix { offset: 0 })
        );
        assert_eq!(journal.read_all().unwrap(), residue);
    }
}
