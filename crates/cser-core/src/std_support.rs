// SPDX-License-Identifier: MPL-2.0

//! Standard-library persistence helpers for host adapters and recovery tests.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use crate::{
    Digest, JournalRecord, JournalRepair, engine::reject_recognized_legacy_journal_prefix,
    scan_journal, scan_journal_to_head,
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
        let bytes = read_all_file(&mut file)?;
        if accepted_revision == 0 || accepted_head.is_zero() {
            if accepted_revision != 0 || !accepted_head.is_zero() {
                return Err(anchor_not_found());
            }
            reject_recognized_legacy_journal_prefix(&bytes).map_err(invalid_journal)?;
            let durable_len = u64::try_from(bytes.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "journal length exceeds u64")
            })?;
            return Ok(Self {
                path,
                file,
                durable_len,
                revision: 0,
                head: Digest::ZERO,
                journal_repair: (!bytes.is_empty())
                    .then_some(JournalRepair::UnanchoredSuffix { offset: 0 }),
                recovery_required: false,
            });
        }
        let full_scan = scan_journal(&bytes);
        let (accepted_len, journal_repair) = match full_scan {
            Ok(scan) => {
                let accepted_index = scan
                    .records()
                    .iter()
                    .position(|record| {
                        record.revision() == accepted_revision && record.digest() == accepted_head
                    })
                    .ok_or_else(anchor_not_found)?;
                let accepted_count = accepted_index + 1;
                let accepted_len = scan.records()[..accepted_count]
                    .iter()
                    .map(|record| record.bytes().len())
                    .sum();
                let repair = if accepted_count < scan.records().len() {
                    Some(JournalRepair::UnanchoredSuffix {
                        offset: accepted_len,
                    })
                } else {
                    scan.torn_tail()
                        .map(|offset| JournalRepair::TornTail { offset })
                };
                (accepted_len, repair)
            }
            Err(full_error) => {
                let scan = scan_journal_to_head(&bytes, accepted_head)
                    .map_err(invalid_journal)?
                    .ok_or_else(|| invalid_journal(full_error))?;
                let record = scan.records().last().ok_or_else(anchor_not_found)?;
                if record.revision() != accepted_revision {
                    return Err(anchor_not_found());
                }
                let accepted_len = scan.unanchored_suffix().unwrap_or_else(|| {
                    scan.records()
                        .iter()
                        .map(|record| record.bytes().len())
                        .sum()
                });
                (
                    accepted_len,
                    Some(JournalRepair::UnanchoredSuffix {
                        offset: accepted_len,
                    }),
                )
            }
        };
        let durable_len = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "journal length exceeds u64")
        })?;
        if accepted_len > bytes.len() {
            return Err(anchor_not_found());
        }
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
        let bytes = read_all_file(&mut self.file)?;
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
            let scan = scan_journal_to_head(&bytes, accepted_head)
                .map_err(invalid_journal)?
                .ok_or_else(anchor_not_found)?;
            scan.records().last().map_or((0, Digest::ZERO), |record| {
                (record.revision(), record.digest())
            })
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
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::{
        BootGeneration, DeviceGeneration, Digest, JournalDecodeError, JournalGeneration,
        JournalRecord, JournalRepair, RegistryInstance, engine::CommandKind, scan_journal,
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

    fn record(base_revision: u64, predecessor: Digest) -> JournalRecord {
        JournalRecord::build(
            base_revision,
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            1,
            JournalGeneration::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            digest(9),
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
