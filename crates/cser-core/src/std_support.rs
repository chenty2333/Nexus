// SPDX-License-Identifier: MPL-2.0

//! Standard-library persistence helpers for host adapters and recovery tests.

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest as Sha2Digest, Sha256};

use crate::{
    Digest, JournalRecord, JournalRepair,
    journal::{
        JOURNAL_RECORD_HEADER_LEN, MAX_JOURNAL_SCAN_BYTES, MAX_JOURNAL_SCAN_RECORDS,
        decode_journal_record_borrowed, journal_record_total_len,
        recognized_legacy_journal_version, scan_journal_borrowed,
    },
    recovery_source::{JournalRecoverySource, RecoverySourceSnapshot},
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

/// Stable coordinates of one locked file-journal recovery view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileRecoverySnapshot {
    durable_len: u64,
    revision: u64,
    head: Digest,
    identity: FileIdentity,
    content_digest: [u8; 32],
}

/// Identity fields which cannot be restored by an ordinary same-length
/// overwrite on Unix.  The journal is a host/Linux adapter; retaining a
/// conservative fallback keeps the crate buildable elsewhere without
/// pretending that the fallback provides Unix inode semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    change_seconds: i64,
    #[cfg(unix)]
    change_nanoseconds: i64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
    len: u64,
}

/// Crate-private positioned recovery view over a locked file journal.
pub(crate) struct FileJournalRecoverySource<'a> {
    journal: &'a mut FileJournal,
}

impl FileJournal {
    /// Borrows this locked journal as one stable positioned recovery source.
    ///
    /// The returned adapter keeps its snapshot token private while still
    /// allowing an embedding to pass the source directly to
    /// [`crate::Engine::recover_from_source`].
    pub fn recovery_source(&mut self) -> impl JournalRecoverySource<Error = io::Error> + '_ {
        FileJournalRecoverySource { journal: self }
    }

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

        let bytes = read_bounded_file(&mut file)?;
        let scan = scan_journal_borrowed(&bytes).map_err(invalid_journal)?;
        let (revision, head) = scan.records().last().map_or((0, Digest::ZERO), |record| {
            (record.meta().revision(), record.digest())
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
        validate_record_revision(record.base_revision(), record.revision())?;
        if observed_len != self.durable_len
            || record.base_revision() != self.revision
            || record.predecessor() != self.head
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal head changed or append record is stale",
            ));
        }
        let record_len = u64::try_from(record.bytes().len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "record length exceeds u64"))?;
        let next_len = observed_len
            .checked_add(record_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "journal length overflow"))?;
        if next_len > MAX_JOURNAL_SCAN_BYTES as u64 {
            return Err(invalid_journal(crate::JournalDecodeError::InputTooLarge {
                limit: MAX_JOURNAL_SCAN_BYTES,
            }));
        }
        self.file.seek(SeekFrom::End(0))?;
        self.recovery_required = true;
        self.file.write_all(record.bytes())?;
        self.file.sync_all()?;
        self.durable_len = next_len;
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
    /// corruption and refuses to truncate a different prefix. A genesis
    /// repair has only the empty accepted prefix; a complete prefix followed
    /// by a torn tail remains ambiguous and is refused.
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
            // Genesis has no record boundary other than byte zero.  In
            // particular, do not let the coordinate pair bypass the caller's
            // accepted-length contract and silently reinterpret a non-empty
            // prefix as genesis.
            if accepted_len != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "genesis repair must use an empty accepted prefix",
                ));
            }
            reject_genesis_records_before_torn_tail(&mut self.file)?;
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
        read_bounded_file(&mut self.file)
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

fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        change_seconds: metadata.ctime(),
        #[cfg(unix)]
        change_nanoseconds: metadata.ctime_nsec(),
        #[cfg(not(unix))]
        modified: metadata.modified().ok(),
        len: metadata.len(),
    }
}

fn current_file_identity(journal: &FileJournal) -> io::Result<FileIdentity> {
    let descriptor = file_identity(&journal.file.metadata()?);
    let path = file_identity(&fs::metadata(&journal.path)?);
    if descriptor != path {
        return Err(recovery_source_changed());
    }
    Ok(descriptor)
}

fn hash_file_prefix(file: &mut File, len: u64) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut scratch = [0u8; 8192];
    let mut offset = 0u64;
    while offset != len {
        let remaining = len - offset;
        let amount = usize::try_from(remaining.min(scratch.len() as u64))
            .map_err(|_| recovery_source_changed())?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut scratch[..amount])?;
        hasher.update(&scratch[..amount]);
        offset = offset
            .checked_add(amount as u64)
            .ok_or_else(recovery_source_changed)?;
    }
    Ok(hasher.finalize().into())
}

fn validate_file_snapshot(
    journal: &mut FileJournal,
    snapshot: FileRecoverySnapshot,
    rehash: bool,
) -> io::Result<()> {
    if journal.recovery_required
        || snapshot.durable_len != journal.durable_len
        || snapshot.revision != journal.revision
        || snapshot.head != journal.head
        || current_file_identity(journal)? != snapshot.identity
    {
        return Err(recovery_source_changed());
    }
    if rehash
        && hash_file_prefix(&mut journal.file, snapshot.durable_len)? != snapshot.content_digest
    {
        return Err(recovery_source_changed());
    }
    Ok(())
}

impl JournalRecoverySource for FileJournalRecoverySource<'_> {
    type Error = io::Error;
    type Snapshot = FileRecoverySnapshot;

    fn begin_snapshot(&mut self) -> Result<RecoverySourceSnapshot<Self::Snapshot>, Self::Error> {
        if self.journal.recovery_required {
            return Err(recovery_source_changed());
        }
        let identity = current_file_identity(self.journal)?;
        if identity.len != self.journal.durable_len {
            return Err(recovery_source_changed());
        }
        let content_digest = hash_file_prefix(&mut self.journal.file, identity.len)?;
        if current_file_identity(self.journal)? != identity {
            return Err(recovery_source_changed());
        }
        let token = FileRecoverySnapshot {
            durable_len: self.journal.durable_len,
            revision: self.journal.revision,
            head: self.journal.head,
            identity,
            content_digest,
        };
        Ok(RecoverySourceSnapshot::new(token, token.durable_len))
    }

    fn read_exact_at(
        &mut self,
        snapshot: Self::Snapshot,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        validate_file_snapshot(self.journal, snapshot, false)?;
        let output_len = u64::try_from(output.len()).map_err(|_| recovery_source_changed())?;
        let end = offset
            .checked_add(output_len)
            .ok_or_else(recovery_source_changed)?;
        if end > snapshot.durable_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "positioned recovery read exceeds the stable journal view",
            ));
        }
        self.journal.file.seek(SeekFrom::Start(offset))?;
        self.journal.file.read_exact(output)?;
        // Detect a same-length write or path replacement which raced this
        // individual read before allowing the decoder to consume its bytes.
        validate_file_snapshot(self.journal, snapshot, false)
    }

    fn validate_snapshot(&mut self, snapshot: Self::Snapshot) -> Result<(), Self::Error> {
        // The final digest is the stable-source certificate. Inode/ctime
        // catches ordinary races cheaply; rehashing also rejects a writer
        // which changed bytes without changing the declared length.
        validate_file_snapshot(self.journal, snapshot, true)
    }
}

/// Reads an entire journal file.
pub fn read_all(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    read_bounded_file(&mut file)
}

fn read_bounded_file(file: &mut File) -> io::Result<Vec<u8>> {
    let declared_len = file.metadata()?.len();
    if declared_len > MAX_JOURNAL_SCAN_BYTES as u64 {
        return Err(invalid_journal(crate::JournalDecodeError::InputTooLarge {
            limit: MAX_JOURNAL_SCAN_BYTES,
        }));
    }
    let capacity = usize::try_from(declared_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "journal length exceeds usize"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| journal_allocation_failed())?;
    file.seek(SeekFrom::Start(0))?;
    file.take((MAX_JOURNAL_SCAN_BYTES as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_JOURNAL_SCAN_BYTES {
        return Err(invalid_journal(crate::JournalDecodeError::InputTooLarge {
            limit: MAX_JOURNAL_SCAN_BYTES,
        }));
    }
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
        let current = decode_journal_record_borrowed(&record).map_err(invalid_journal)?;
        let meta = current.meta();
        if let Some((previous_revision, previous_head)) = previous {
            validate_record_successor(
                meta.base_revision(),
                meta.revision(),
                meta.predecessor(),
                previous_revision,
                previous_head,
            )?;
        } else {
            validate_record_start(
                meta.base_revision(),
                meta.revision(),
                meta.predecessor(),
                current.whole_state_checkpoint().is_some(),
            )?;
        }
        prefix_len = prefix_len
            .checked_add(total_len)
            .ok_or_else(|| invalid_journal(crate::JournalDecodeError::LengthOverflow))?;
        record_count += 1;

        if current.digest() == accepted_head {
            if meta.revision() != accepted_revision {
                return Err(anchor_not_found());
            }
            return Ok(prefix_len);
        }
        previous = Some((meta.revision(), current.digest()));
    }
}

fn validate_record_start(
    base_revision: u64,
    revision: u64,
    predecessor: Digest,
    is_checkpoint: bool,
) -> io::Result<()> {
    validate_record_revision(base_revision, revision)?;
    if !is_checkpoint && (base_revision != 0 || !predecessor.is_zero()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal record chain does not begin at genesis",
        ));
    }
    Ok(())
}

fn validate_record_successor(
    base_revision: u64,
    revision: u64,
    predecessor: Digest,
    previous_revision: u64,
    previous_head: Digest,
) -> io::Result<()> {
    validate_record_revision(base_revision, revision)?;
    if base_revision != previous_revision || predecessor != previous_head {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal record chain is discontinuous",
        ));
    }
    Ok(())
}

fn validate_record_revision(base_revision: u64, revision: u64) -> io::Result<()> {
    let expected = base_revision.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "journal record base revision overflows",
        )
    })?;
    if revision != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal record revision does not advance its base revision",
        ));
    }
    Ok(())
}

fn journal_allocation_failed() -> io::Error {
    io::Error::other("journal record allocation failed during anchored recovery")
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

/// Refuses to erase a complete accepted-looking prefix together with a torn
/// suffix while the trusted anchor still names genesis.  A complete-only
/// unanchored first append remains the existing legal genesis repair case;
/// the combination with a torn tail is ambiguous and must be recovered under
/// a non-genesis anchored boundary instead.
fn reject_genesis_records_before_torn_tail(file: &mut File) -> io::Result<()> {
    let bytes = read_bounded_file(file)?;
    let scan = scan_journal_borrowed(&bytes).map_err(invalid_journal)?;
    if !scan.records().is_empty() && scan.torn_tail().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "genesis repair cannot discard complete records before a torn tail",
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

fn recovery_source_changed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "file journal changed during positioned recovery",
    )
}

fn anchor_not_found() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "trusted journal anchor does not name a validated prefix",
    )
}

fn invalid_journal(error: crate::JournalDecodeError) -> io::Error {
    let message = match error {
        crate::JournalDecodeError::ChainMismatch { offset: 0 } => {
            return io::Error::new(
                io::ErrorKind::InvalidData,
                "journal record chain does not begin at genesis",
            );
        }
        crate::JournalDecodeError::ChainMismatch { .. } => {
            return io::Error::new(
                io::ErrorKind::InvalidData,
                "journal record chain is discontinuous",
            );
        }
        crate::JournalDecodeError::RevisionOverflow => {
            return io::Error::new(
                io::ErrorKind::InvalidData,
                "journal record base revision overflows",
            );
        }
        _ => format!("invalid CSER journal: {error:?}"),
    };
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Cursor, Read, Seek, SeekFrom, Write},
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    use crate::journal::{
        MAX_JOURNAL_SCAN_BYTES, MAX_JOURNAL_SCAN_RECORDS, recovery_source::JournalRecoverySource,
    };
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

    fn checkpoint_record(base_revision: u64, predecessor: Digest) -> JournalRecord {
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
            CommandKind::WholeStateCheckpointV1 {
                state: Arc::from(Vec::<u8>::new().into_boxed_slice()),
                projection: digest(8),
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
    fn open_rejects_a_sparse_file_before_reading_past_the_scan_budget() {
        let temp = TempJournal::new("sparse-budget");
        let file = std::fs::File::create(&temp.path).unwrap();
        file.set_len((MAX_JOURNAL_SCAN_BYTES as u64) + 1).unwrap();
        drop(file);

        let error = FileJournal::open(&temp.path).expect_err("oversized input must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("InputTooLarge"));
        let error = super::read_all(&temp.path).expect_err("unbounded read must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("InputTooLarge"));
    }

    #[test]
    fn append_rejects_a_budget_overflow_before_mutating_file_or_coordinates() {
        let temp = TempJournal::new("append-budget");
        let first = record(0, Digest::ZERO);
        let record_len = u64::try_from(first.bytes().len()).unwrap();
        let durable_len = (MAX_JOURNAL_SCAN_BYTES as u64)
            .checked_sub(record_len)
            .unwrap()
            .checked_add(1)
            .unwrap();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&temp.path)
            .unwrap();
        file.set_len(durable_len).unwrap();
        let mut journal = super::FileJournal {
            path: temp.path.clone(),
            file,
            durable_len,
            revision: 0,
            head: Digest::ZERO,
            journal_repair: None,
            recovery_required: false,
        };

        let error = journal
            .append(&first)
            .expect_err("append must not create an un-reopenable journal");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("InputTooLarge"));
        assert_eq!(journal.file.metadata().unwrap().len(), durable_len);
        assert_eq!(journal.durable_len, durable_len);
        assert_eq!(journal.revision, 0);
        assert_eq!(journal.head, Digest::ZERO);
        assert!(!journal.recovery_required);
    }

    #[test]
    fn open_rejects_a_non_genesis_first_record() {
        let temp = TempJournal::new("non-genesis-first-record");
        let first = record(7, digest(42));
        std::fs::write(&temp.path, first.bytes()).unwrap();

        let error =
            FileJournal::open(&temp.path).expect_err("ordinary journal must begin at genesis");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "journal record chain does not begin at genesis"
        );
    }

    #[test]
    fn open_rejects_revision_gap_and_wrong_predecessor() {
        for (label, second) in [
            ("revision-gap", record(2, digest(7))),
            ("wrong-predecessor", record(1, digest(0xaa))),
        ] {
            let temp = TempJournal::new(label);
            let first = record(0, Digest::ZERO);
            let mut bytes = first.bytes().to_vec();
            bytes.extend_from_slice(second.bytes());
            std::fs::write(&temp.path, bytes).unwrap();

            let error =
                FileJournal::open(&temp.path).expect_err("broken journal chain must fail closed");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "journal record chain is discontinuous");
        }
    }

    #[test]
    fn open_accepts_a_leading_checkpoint_with_a_compressed_base() {
        let temp = TempJournal::new("checkpoint-base");
        let first = checkpoint_record(42, digest(42));
        let second = record(first.revision(), first.digest());
        let mut bytes = first.bytes().to_vec();
        bytes.extend_from_slice(second.bytes());
        std::fs::write(&temp.path, bytes).unwrap();

        let journal = FileJournal::open(&temp.path).expect("engine validates the checkpoint image");
        assert_eq!(journal.revision(), second.revision());
        assert_eq!(journal.head(), second.digest());
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
        let error = journal
            .read_all()
            .expect_err("reading an oversized unanchored suffix must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("InputTooLarge"));
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
    fn anchored_prefix_rejects_a_non_genesis_first_record() {
        let temp = TempJournal::new("anchored-non-genesis");
        let first = record(7, digest(42));
        std::fs::write(&temp.path, first.bytes()).unwrap();

        let error = FileJournal::open_anchored(&temp.path, first.revision(), first.digest())
            .expect_err("ordinary anchored journal must begin at genesis");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "journal record chain does not begin at genesis"
        );
    }

    #[test]
    fn anchored_prefix_accepts_a_leading_checkpoint_with_a_compressed_base() {
        let temp = TempJournal::new("anchored-checkpoint-base");
        let first = checkpoint_record(42, digest(42));
        std::fs::write(&temp.path, first.bytes()).unwrap();

        let journal = FileJournal::open_anchored(&temp.path, first.revision(), first.digest())
            .expect("the trusted anchor and engine validate the checkpoint base");
        assert_eq!(journal.revision(), first.revision());
        assert_eq!(journal.head(), first.digest());
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
    fn genesis_repair_rejects_valid_records_followed_by_a_torn_tail() {
        let temp = TempJournal::new("genesis-valid-prefix-torn-tail");
        let first = record(0, Digest::ZERO);
        let second = record(first.revision(), first.digest());
        let mut bytes = first.bytes().to_vec();
        bytes.extend_from_slice(&second.bytes()[..second.bytes().len() / 2]);
        std::fs::write(&temp.path, &bytes).unwrap();

        let mut journal = FileJournal::open_anchored(&temp.path, 0, Digest::ZERO).unwrap();
        let error = journal
            .repair_to_anchored_prefix(0, 0, Digest::ZERO)
            .expect_err("genesis repair must not discard a valid prefix plus torn tail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(journal.read_all().unwrap(), bytes);
        assert!(!journal.recovery_required());
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

    #[test]
    fn anchored_open_rejects_profile_six_before_genesis_repair() {
        let temp = TempJournal::new("profile-six-genesis-prefix");
        let bytes = Vec::from(*b"CSERJ10\0");
        std::fs::write(&temp.path, &bytes).unwrap();

        let error = FileJournal::open_anchored(&temp.path, 0, Digest::ZERO)
            .expect_err("profile six must not be reclassified as repairable residue");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "invalid CSER journal: UnsupportedVersion { version: 10 }"
        );
        assert_eq!(std::fs::read(&temp.path).unwrap(), bytes);
    }

    #[test]
    fn file_journal_positioned_snapshot_reads_without_materializing_the_image() {
        let temp = TempJournal::new("positioned-recovery-source");
        let first = record(0, Digest::ZERO);
        std::fs::write(&temp.path, first.bytes()).unwrap();
        let mut journal = FileJournal::open(&temp.path).unwrap();
        let mut source = journal.recovery_source();
        let snapshot = source.begin_snapshot().unwrap();
        assert_eq!(snapshot.logical_len(), first.bytes().len() as u64);

        for chunk_len in [1, 7, 31, 511, 512, 4096] {
            let mut actual = vec![0; chunk_len.min(first.bytes().len())];
            source
                .read_exact_at(snapshot.token(), 0, &mut actual)
                .unwrap();
            assert_eq!(actual, first.bytes()[..actual.len()]);
        }
        source.validate_snapshot(snapshot.token()).unwrap();

        std::fs::OpenOptions::new()
            .append(true)
            .open(&temp.path)
            .unwrap()
            .write_all(b"uncoordinated suffix")
            .unwrap();
        assert!(source.validate_snapshot(snapshot.token()).is_err());
    }

    #[test]
    fn file_journal_positioned_snapshot_rejects_same_length_overwrite() {
        let temp = TempJournal::new("positioned-recovery-overwrite");
        let first = record(0, Digest::ZERO);
        std::fs::write(&temp.path, first.bytes()).unwrap();
        let mut journal = FileJournal::open(&temp.path).unwrap();
        let mut source = journal.recovery_source();
        let snapshot = source.begin_snapshot().unwrap();

        let mut replacement = vec![0xa5; first.bytes().len()];
        replacement[..8].copy_from_slice(&first.bytes()[..8]);
        let mut bypass = std::fs::OpenOptions::new()
            .write(true)
            .open(&temp.path)
            .unwrap();
        bypass.seek(SeekFrom::Start(0)).unwrap();
        bypass.write_all(&replacement).unwrap();
        bypass.sync_all().unwrap();

        assert!(source.validate_snapshot(snapshot.token()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_journal_positioned_snapshot_rejects_path_replacement() {
        let temp = TempJournal::new("positioned-recovery-path-replacement");
        let first = record(0, Digest::ZERO);
        std::fs::write(&temp.path, first.bytes()).unwrap();
        let mut journal = FileJournal::open(&temp.path).unwrap();
        let mut source = journal.recovery_source();
        let snapshot = source.begin_snapshot().unwrap();

        let replacement = temp.path.with_extension("replacement");
        std::fs::write(&replacement, first.bytes()).unwrap();
        std::fs::rename(&replacement, &temp.path).unwrap();

        assert!(source.validate_snapshot(snapshot.token()).is_err());
    }
}
