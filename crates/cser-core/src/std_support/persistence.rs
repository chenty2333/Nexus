// SPDX-License-Identifier: MPL-2.0

//! Host reference implementation of the trusted-anchor protocol.
//!
//! This module exercises atomic replacement, barriers, compare-and-advance,
//! and cold reopen behavior. A normal file remains rollbackable by the host and
//! therefore **does not** provide production anti-rollback security.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
};

use sha2::{Digest as _, Sha256};

use crate::{
    BootGeneration, DeviceGeneration, Digest, Freshness, JournalGeneration,
    PersistenceProtocolError, RecoveryBinding, RecoveryLease, TrustedAnchorBackend,
    TrustedAnchorSnapshot,
};

const MAGIC: [u8; 8] = *b"CSERAN2\0";
const VERSION: u16 = 2;
const BODY_LEN: usize = 186;
const ENCODED_LEN: usize = BODY_LEN + 32;

/// One-shot crash point in the host reference anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostAnchorFailpoint {
    /// Execute without an injected failure.
    None,
    /// Fail after the replacement file is durable but before atomic rename.
    BeforeAtomicReplace,
    /// Atomically install and sync the replacement, then lose its acknowledgement.
    AfterAtomicReplaceBeforeReturn,
    /// Atomically install and sync the replacement, then panic before the
    /// caller receives an acknowledgement.
    PanicAfterAtomicReplaceBeforeReturn,
}

/// Failure from [`HostFileTrustedAnchor`].
#[derive(Debug)]
pub enum HostAnchorError {
    /// Host filesystem operation failed.
    Io(io::Error),
    /// The stored bytes are corrupt or structurally invalid.
    Corrupt,
    /// The caller violated the trusted-anchor state-transition contract.
    Protocol(PersistenceProtocolError),
    /// A configured crash point fired.
    Injected(HostAnchorFailpoint),
    /// The atomic replacement panicked after entering the filesystem
    /// operation. The handle is permanently poisoned and must be reopened.
    AtomicWritePanicked,
    /// This handle observed an ambiguous filesystem mutation. Drop and
    /// reopen it before reserving, advancing, or observing its state.
    RecoveryRequired,
}

impl From<io::Error> for HostAnchorError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<PersistenceProtocolError> for HostAnchorError {
    fn from(error: PersistenceProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostAnchorState {
    committed: TrustedAnchorSnapshot,
    issued: Freshness,
}

/// Rollbackable host-file fixture for a production-shaped trusted anchor.
///
/// Updates use write, file sync, atomic rename, and parent-directory sync while
/// an advisory single-writer lock is held. Those mechanics test the protocol's
/// crash windows, but cannot turn an ordinary file into a non-rollback root of
/// trust.
#[derive(Debug)]
pub struct HostFileTrustedAnchor {
    path: PathBuf,
    lock: File,
    state: HostAnchorState,
    failpoint: HostAnchorFailpoint,
    recovery_required: bool,
}

impl HostFileTrustedAnchor {
    /// Opens an existing anchor or creates a genesis anchor.
    pub fn open_or_initialize(
        path: impl AsRef<Path>,
        binding: RecoveryBinding,
        initial_freshness: Freshness,
        initial_projection: Digest,
    ) -> Result<Self, HostAnchorError> {
        let path = path.as_ref().to_path_buf();
        let lock_path = path.with_extension("lock");
        let lock_is_new = !lock_path.exists();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        lock.try_lock()
            .map_err(|error| HostAnchorError::Io(error.into()))?;
        if lock_is_new {
            lock.sync_all()?;
            sync_parent_directory(&lock_path)?;
        }

        let state = if path.exists() {
            decode_state(&fs::read(&path)?)?
        } else {
            let committed = TrustedAnchorSnapshot::from_trusted_backend(
                binding,
                initial_freshness,
                0,
                Digest::ZERO,
                initial_projection,
            )?;
            let state = HostAnchorState {
                committed,
                issued: initial_freshness,
            };
            write_atomic(&path, state, HostAnchorFailpoint::None)?;
            state
        };
        Ok(Self {
            path,
            lock,
            state,
            failpoint: HostAnchorFailpoint::None,
            recovery_required: false,
        })
    }

    /// Configures a one-shot failure for the next state update.
    pub fn set_failpoint(&mut self, failpoint: HostAnchorFailpoint) {
        self.failpoint = failpoint;
    }

    /// Returns the currently decoded host-file state while this handle is
    /// still authoritative.
    ///
    /// After an ambiguous filesystem error the in-memory state may no longer
    /// describe the durable file (for example, an atomic rename may have
    /// succeeded before its acknowledgement was lost). Such observations are
    /// therefore rejected until this object is dropped and reopened.
    pub fn committed(&self) -> Result<TrustedAnchorSnapshot, HostAnchorError> {
        self.ensure_usable()?;
        Ok(self.state.committed)
    }

    /// Returns whether this handle has observed an ambiguous filesystem
    /// mutation and must be dropped and reopened.
    pub const fn recovery_required(&self) -> bool {
        self.recovery_required
    }

    fn ensure_usable(&self) -> Result<(), HostAnchorError> {
        if self.recovery_required {
            Err(HostAnchorError::RecoveryRequired)
        } else {
            Ok(())
        }
    }

    fn replace(&mut self, state: HostAnchorState) -> Result<(), HostAnchorError> {
        self.ensure_usable()?;
        let failpoint = core::mem::replace(&mut self.failpoint, HostAnchorFailpoint::None);
        match catch_unwind(AssertUnwindSafe(|| {
            write_atomic(&self.path, state, failpoint)
        })) {
            Ok(Ok(())) => {
                // The file and its parent directory are durable before this
                // in-memory authority moves. This assignment must remain the
                // final fallible-operation boundary.
                self.state = state;
                Ok(())
            }
            Ok(Err(error)) => {
                self.recovery_required = true;
                Err(error)
            }
            Err(_) => {
                self.recovery_required = true;
                Err(HostAnchorError::AtomicWritePanicked)
            }
        }
    }
}

impl Drop for HostFileTrustedAnchor {
    fn drop(&mut self) {
        let _ = File::unlock(&self.lock);
    }
}

impl TrustedAnchorBackend for HostFileTrustedAnchor {
    type Error = HostAnchorError;

    fn reserve_recovery_epoch(
        &mut self,
        binding: RecoveryBinding,
        observed_device: DeviceGeneration,
    ) -> Result<RecoveryLease, Self::Error> {
        self.ensure_usable()?;
        if binding != self.state.committed.binding() {
            return Err(PersistenceProtocolError::BindingMismatch.into());
        }
        if observed_device.get() < self.state.committed.committed_freshness().device().get()
            || observed_device.get() < self.state.issued.device().get()
        {
            return Err(PersistenceProtocolError::StaleFreshness.into());
        }
        let next_boot = self
            .state
            .issued
            .boot()
            .get()
            .checked_add(1)
            .and_then(|value| BootGeneration::new(value).ok())
            .ok_or(PersistenceProtocolError::StaleFreshness)?;
        let next_journal = self
            .state
            .issued
            .journal()
            .get()
            .checked_add(1)
            .and_then(|value| JournalGeneration::new(value).ok())
            .ok_or(PersistenceProtocolError::StaleFreshness)?;
        let next = Freshness::new(next_boot, binding.registry(), observed_device, next_journal);
        let replacement = HostAnchorState {
            committed: self.state.committed,
            issued: next,
        };
        self.replace(replacement)?;
        RecoveryLease::from_trusted_backend(replacement.committed, next).map_err(Into::into)
    }

    fn compare_and_advance(
        &mut self,
        expected: TrustedAnchorSnapshot,
        replacement: TrustedAnchorSnapshot,
    ) -> Result<(), Self::Error> {
        self.ensure_usable()?;
        if expected != self.state.committed {
            return Err(PersistenceProtocolError::StaleJournalHead.into());
        }
        if replacement.binding() != expected.binding()
            || expected.revision().checked_add(1) != Some(replacement.revision())
            || replacement.committed_freshness().boot().get()
                < expected.committed_freshness().boot().get()
            || replacement.committed_freshness().journal().get()
                < expected.committed_freshness().journal().get()
            || replacement.committed_freshness().device().get()
                < expected.committed_freshness().device().get()
            || (replacement.committed_freshness() != expected.committed_freshness()
                && replacement.committed_freshness() != self.state.issued)
        {
            return Err(PersistenceProtocolError::StaleFreshness.into());
        }
        self.replace(HostAnchorState {
            committed: replacement,
            issued: self.state.issued,
        })
    }
}

fn write_atomic(
    path: &Path,
    state: HostAnchorState,
    failpoint: HostAnchorFailpoint,
) -> Result<(), HostAnchorError> {
    let temporary = path.with_extension(format!("next-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&encode_state(state))?;
    file.sync_all()?;
    if failpoint == HostAnchorFailpoint::BeforeAtomicReplace {
        return Err(HostAnchorError::Injected(failpoint));
    }
    fs::rename(&temporary, path)?;
    sync_parent_directory(path)?;
    if failpoint == HostAnchorFailpoint::AfterAtomicReplaceBeforeReturn {
        return Err(HostAnchorError::Injected(failpoint));
    }
    if failpoint == HostAnchorFailpoint::PanicAfterAtomicReplaceBeforeReturn {
        panic!("injected host trusted-anchor panic after atomic replacement");
    }
    Ok(())
}

fn encode_state(state: HostAnchorState) -> [u8; ENCODED_LEN] {
    let mut bytes = [0u8; ENCODED_LEN];
    let mut cursor = 0;
    put(&mut bytes, &mut cursor, &MAGIC);
    put(&mut bytes, &mut cursor, &VERSION.to_le_bytes());
    let profile = state.committed.binding().profile();
    put(&mut bytes, &mut cursor, &profile.core_api().to_le_bytes());
    put(
        &mut bytes,
        &mut cursor,
        &profile.journal_schema().to_le_bytes(),
    );
    put(
        &mut bytes,
        &mut cursor,
        &profile.projection_schema().to_le_bytes(),
    );
    put(
        &mut bytes,
        &mut cursor,
        &profile.checkpoint_schema().to_le_bytes(),
    );
    put(
        &mut bytes,
        &mut cursor,
        &state.committed.binding().world().get().to_le_bytes(),
    );
    put(
        &mut bytes,
        &mut cursor,
        &state.committed.binding().catalog_digest().bytes(),
    );
    put(
        &mut bytes,
        &mut cursor,
        &state.committed.binding().registry().get().to_le_bytes(),
    );
    put(
        &mut bytes,
        &mut cursor,
        &state
            .committed
            .committed_freshness()
            .boot()
            .get()
            .to_le_bytes(),
    );
    put(
        &mut bytes,
        &mut cursor,
        &state
            .committed
            .committed_freshness()
            .device()
            .get()
            .to_le_bytes(),
    );
    put(
        &mut bytes,
        &mut cursor,
        &state
            .committed
            .committed_freshness()
            .journal()
            .get()
            .to_le_bytes(),
    );
    put(
        &mut bytes,
        &mut cursor,
        &state.committed.revision().to_le_bytes(),
    );
    put(&mut bytes, &mut cursor, &state.committed.head().bytes());
    put(
        &mut bytes,
        &mut cursor,
        &state.committed.projection().bytes(),
    );
    put(
        &mut bytes,
        &mut cursor,
        &state.issued.boot().get().to_le_bytes(),
    );
    put(
        &mut bytes,
        &mut cursor,
        &state.issued.device().get().to_le_bytes(),
    );
    put(
        &mut bytes,
        &mut cursor,
        &state.issued.journal().get().to_le_bytes(),
    );
    debug_assert_eq!(cursor, BODY_LEN);
    let checksum: [u8; 32] = Sha256::digest(&bytes[..BODY_LEN]).into();
    bytes[BODY_LEN..].copy_from_slice(&checksum);
    bytes
}

fn decode_state(bytes: &[u8]) -> Result<HostAnchorState, HostAnchorError> {
    if bytes.len() != ENCODED_LEN
        || bytes[..8] != MAGIC
        || bytes[8..10] != VERSION.to_le_bytes()
        || Sha256::digest(&bytes[..BODY_LEN]).as_slice() != &bytes[BODY_LEN..]
    {
        return Err(HostAnchorError::Corrupt);
    }
    let mut cursor = 10;
    let profile = crate::RecoveryProfile::new(
        take_u16(bytes, &mut cursor)?,
        take_u16(bytes, &mut cursor)?,
        take_u16(bytes, &mut cursor)?,
        take_u16(bytes, &mut cursor)?,
    )
    .map_err(|_| HostAnchorError::Corrupt)?;
    if profile != crate::RecoveryProfile::current() {
        return Err(HostAnchorError::Corrupt);
    }
    let world =
        crate::WorldId::new(take_u64(bytes, &mut cursor)?).map_err(|_| HostAnchorError::Corrupt)?;
    let catalog = Digest::new(take_array(bytes, &mut cursor)?);
    let registry = crate::RegistryInstance::new(take_u64(bytes, &mut cursor)?)
        .map_err(|_| HostAnchorError::Corrupt)?;
    let binding = RecoveryBinding::new(profile, world, catalog, registry)
        .map_err(|_| HostAnchorError::Corrupt)?;
    let committed = Freshness::new(
        BootGeneration::new(take_u64(bytes, &mut cursor)?).map_err(|_| HostAnchorError::Corrupt)?,
        registry,
        DeviceGeneration::new(take_u64(bytes, &mut cursor)?)
            .map_err(|_| HostAnchorError::Corrupt)?,
        JournalGeneration::new(take_u64(bytes, &mut cursor)?)
            .map_err(|_| HostAnchorError::Corrupt)?,
    );
    let revision = take_u64(bytes, &mut cursor)?;
    let head = Digest::new(take_array(bytes, &mut cursor)?);
    let projection = Digest::new(take_array(bytes, &mut cursor)?);
    let issued = Freshness::new(
        BootGeneration::new(take_u64(bytes, &mut cursor)?).map_err(|_| HostAnchorError::Corrupt)?,
        registry,
        DeviceGeneration::new(take_u64(bytes, &mut cursor)?)
            .map_err(|_| HostAnchorError::Corrupt)?,
        JournalGeneration::new(take_u64(bytes, &mut cursor)?)
            .map_err(|_| HostAnchorError::Corrupt)?,
    );
    if cursor != BODY_LEN
        || issued.boot().get() < committed.boot().get()
        || issued.journal().get() < committed.journal().get()
        || issued.device().get() < committed.device().get()
    {
        return Err(HostAnchorError::Corrupt);
    }
    let committed = TrustedAnchorSnapshot::from_trusted_backend(
        binding, committed, revision, head, projection,
    )?;
    Ok(HostAnchorState { committed, issued })
}

fn put<const N: usize>(bytes: &mut [u8], cursor: &mut usize, value: &[u8; N]) {
    bytes[*cursor..*cursor + N].copy_from_slice(value);
    *cursor += N;
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, HostAnchorError> {
    Ok(u64::from_le_bytes(take_array(bytes, cursor)?))
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, HostAnchorError> {
    Ok(u16::from_le_bytes(take_array(bytes, cursor)?))
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], HostAnchorError> {
    let end = cursor.checked_add(N).ok_or(HostAnchorError::Corrupt)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(HostAnchorError::Corrupt)?
        .try_into()
        .map_err(|_| HostAnchorError::Corrupt)?;
    *cursor = end;
    Ok(value)
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::{CatalogSet, RecoveryProfile, RegistryInstance, WorldId, standard_catalog};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempAnchor {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TempAnchor {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "nexus-cser-host-anchor-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("create isolated anchor test directory");
            let path = directory.join("anchor.bin");
            Self { directory, path }
        }
    }

    impl Drop for TempAnchor {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn binding() -> RecoveryBinding {
        RecoveryBinding::new(
            RecoveryProfile::current(),
            WorldId::new(7).expect("test world is nonzero"),
            CatalogSet::new(&[standard_catalog()])
                .expect("test catalog is valid")
                .digest(),
            RegistryInstance::new(3).expect("test registry is nonzero"),
        )
        .expect("test recovery binding is valid")
    }

    fn freshness(boot: u64, device: u64, journal: u64) -> Freshness {
        Freshness::new(
            BootGeneration::new(boot).expect("test boot is nonzero"),
            binding().registry(),
            DeviceGeneration::new(device).expect("test device is nonzero"),
            JournalGeneration::new(journal).expect("test journal is nonzero"),
        )
    }

    fn open(temp: &TempAnchor) -> HostFileTrustedAnchor {
        HostFileTrustedAnchor::open_or_initialize(
            &temp.path,
            binding(),
            freshness(1, 1, 1),
            Digest::new([0xabu8; 32]),
        )
        .expect("open host anchor")
    }

    #[test]
    fn ambiguous_before_rename_poison_rejects_reuse_and_reopens_old_truth() {
        let temp = TempAnchor::new("before-rename");
        let mut anchor = open(&temp);
        let old = anchor.committed().expect("unpoisoned observation");

        anchor.set_failpoint(HostAnchorFailpoint::BeforeAtomicReplace);
        let error = anchor
            .reserve_recovery_epoch(binding(), DeviceGeneration::new(2).unwrap())
            .expect_err("injected pre-rename failure");
        assert!(matches!(
            error,
            HostAnchorError::Injected(HostAnchorFailpoint::BeforeAtomicReplace)
        ));
        assert!(anchor.recovery_required());
        assert!(matches!(
            anchor.committed(),
            Err(HostAnchorError::RecoveryRequired)
        ));

        let replacement = TrustedAnchorSnapshot::from_trusted_backend(
            binding(),
            old.committed_freshness(),
            1,
            Digest::new([0x11; 32]),
            Digest::new([0x22; 32]),
        )
        .expect("test replacement is valid");
        assert!(matches!(
            anchor.compare_and_advance(old, replacement),
            Err(HostAnchorError::RecoveryRequired)
        ));

        drop(anchor);
        let mut reopened = open(&temp);
        assert_eq!(reopened.committed().expect("reopened observation"), old);
        let lease = reopened
            .reserve_recovery_epoch(binding(), DeviceGeneration::new(2).unwrap())
            .expect("reopened old durable state remains usable");
        assert_eq!(lease.next_freshness(), freshness(2, 2, 2));
    }

    #[test]
    fn ambiguous_after_rename_poison_reopens_at_durable_replacement() {
        let temp = TempAnchor::new("after-rename");
        let mut anchor = open(&temp);
        let old = anchor.committed().expect("unpoisoned observation");

        anchor.set_failpoint(HostAnchorFailpoint::AfterAtomicReplaceBeforeReturn);
        let error = anchor
            .reserve_recovery_epoch(binding(), DeviceGeneration::new(2).unwrap())
            .expect_err("injected lost acknowledgement");
        assert!(matches!(
            error,
            HostAnchorError::Injected(HostAnchorFailpoint::AfterAtomicReplaceBeforeReturn)
        ));
        assert!(anchor.recovery_required());
        drop(anchor);

        let mut reopened = open(&temp);
        assert_eq!(reopened.committed().expect("reopened observation"), old);
        // The failed reserve installed the new issued epoch before losing its
        // acknowledgement. Reopening must use that durable truth rather than
        // the stale in-memory state from the dropped handle.
        let lease = reopened
            .reserve_recovery_epoch(binding(), DeviceGeneration::new(2).unwrap())
            .expect("reopened durable state remains usable");
        assert_eq!(lease.next_freshness(), freshness(3, 2, 3));
    }

    #[test]
    fn precondition_errors_do_not_poison_the_handle() {
        let temp = TempAnchor::new("precondition");
        let mut anchor = open(&temp);
        let old = anchor.committed().expect("unpoisoned observation");
        let wrong_binding = RecoveryBinding::new(
            RecoveryProfile::current(),
            old.binding().world(),
            Digest::new([0x33; 32]),
            old.binding().registry(),
        )
        .expect("wrong binding is structurally valid");

        assert!(matches!(
            anchor.reserve_recovery_epoch(wrong_binding, DeviceGeneration::new(2).unwrap()),
            Err(HostAnchorError::Protocol(
                PersistenceProtocolError::BindingMismatch
            ))
        ));
        assert!(!anchor.recovery_required());
        assert_eq!(
            anchor.committed().expect("precondition keeps state usable"),
            old
        );
    }
}
