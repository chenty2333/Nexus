// SPDX-License-Identifier: MPL-2.0

//! Host reference implementation of the trusted-anchor protocol.
//!
//! This module exercises atomic replacement, barriers, compare-and-advance,
//! and cold reopen behavior. A normal file remains rollbackable by the host and
//! therefore **does not** provide production anti-rollback security.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
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
const BODY_LEN: usize = 194;
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
        })
    }

    /// Configures a one-shot failure for the next state update.
    pub fn set_failpoint(&mut self, failpoint: HostAnchorFailpoint) {
        self.failpoint = failpoint;
    }

    /// Returns the currently decoded host-file state.
    pub const fn committed(&self) -> TrustedAnchorSnapshot {
        self.state.committed
    }

    fn replace(&mut self, state: HostAnchorState) -> Result<(), HostAnchorError> {
        let failpoint = core::mem::replace(&mut self.failpoint, HostAnchorFailpoint::None);
        write_atomic(&self.path, state, failpoint)?;
        self.state = state;
        Ok(())
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
        let next = Freshness::new(
            next_boot,
            binding.registry(),
            binding.binding().get(),
            observed_device,
            next_journal,
        )
        .map_err(|_| PersistenceProtocolError::InvalidAnchor)?;
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
        &state.committed.binding().binding().get().to_le_bytes(),
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
    let binding_value = take_u64(bytes, &mut cursor)?;
    let authority_binding = crate::AuthorityBindingGeneration::new(binding_value)
        .map_err(|_| HostAnchorError::Corrupt)?;
    let binding = RecoveryBinding::new(profile, world, catalog, registry, authority_binding)
        .map_err(|_| HostAnchorError::Corrupt)?;
    let committed = Freshness::new(
        BootGeneration::new(take_u64(bytes, &mut cursor)?).map_err(|_| HostAnchorError::Corrupt)?,
        registry,
        binding_value,
        DeviceGeneration::new(take_u64(bytes, &mut cursor)?)
            .map_err(|_| HostAnchorError::Corrupt)?,
        JournalGeneration::new(take_u64(bytes, &mut cursor)?)
            .map_err(|_| HostAnchorError::Corrupt)?,
    )
    .map_err(|_| HostAnchorError::Corrupt)?;
    let revision = take_u64(bytes, &mut cursor)?;
    let head = Digest::new(take_array(bytes, &mut cursor)?);
    let projection = Digest::new(take_array(bytes, &mut cursor)?);
    let issued = Freshness::new(
        BootGeneration::new(take_u64(bytes, &mut cursor)?).map_err(|_| HostAnchorError::Corrupt)?,
        registry,
        binding_value,
        DeviceGeneration::new(take_u64(bytes, &mut cursor)?)
            .map_err(|_| HostAnchorError::Corrupt)?,
        JournalGeneration::new(take_u64(bytes, &mut cursor)?)
            .map_err(|_| HostAnchorError::Corrupt)?,
    )
    .map_err(|_| HostAnchorError::Corrupt)?;
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
