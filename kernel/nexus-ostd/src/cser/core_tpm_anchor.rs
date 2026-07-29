// SPDX-License-Identifier: MPL-2.0

//! TPM2 NV trusted-anchor provider for persistent CSER recovery.
//!
//! A single ordinary NV index is not used as a commit record.  TPM2 has no
//! ordinary-NV compare-and-swap command, and a power loss during a multi-byte
//! update must not make a partially written value authoritative.  This
//! provider instead uses two independent selector protocols:
//!
//! - two tip slots plus one non-orderly TPM2 NV counter; and
//! - two recovery-lease slots plus a second non-orderly TPM2 NV counter.
//!
//! An update writes and reads back the inactive slot first, then performs one
//! `TPM2_NV_Increment`.  The counter value selects the authoritative slot by
//! parity.  A crash before the increment leaves the old slot selected.  A
//! crash after the increment selects the complete, read-back-verified new
//! slot.  A lost command acknowledgement is therefore resolved by reopening
//! the provider and reading the counter.
//!
//! Ordinary NV also has no transaction lock spanning slot write and counter
//! increment. Nexus therefore enforces exactly one open provider instance for
//! the lifetime of a boot; construction of a second instance fails before any
//! TPM command. This is the same single-writer authority owned by the portable
//! core runtime, not a claim that the TPM offers multi-writer CAS.
//!
//! The counters and ordinary slots must have `TPMA_NV_ORDERLY` clear.  The TPM
//! specification then requires each successful update to reach the NV version
//! rather than an orderly-shutdown-only RAM copy.  Provisioning is deliberately
//! out of band: runtime code receives only an index auth value and cannot
//! define, undefine, clear, or reprovision the indices.
//!
//! Security boundary:
//!
//! - a physical TPM whose platform/owner hierarchy authorization is withheld
//!   from the runtime is a non-rollback platform root for this protocol;
//! - QEMU `tpm-tis` plus swtpm exercises the real TPM2 command and TIS paths,
//!   but the host can roll back the swtpm state directory, so it is not
//!   physical anti-rollback evidence;
//! - an index auth value compiled into a kernel image is test provisioning,
//!   not a production secret-distribution design.

use alloc::vec::Vec;
use core::{
    hint::spin_loop,
    sync::atomic::{AtomicBool, Ordering},
};

use cser_core::{
    BootGeneration, DeviceGeneration, Digest, Freshness, JournalGeneration,
    PersistenceProtocolError, RecoveryBinding, RecoveryLease, RegistryInstance,
    TrustedAnchorBackend, TrustedAnchorSnapshot,
};
use ostd::{
    io::IoMem,
    mm::VmIoOnce,
    power::{ExitCode, poweroff},
    prelude::*,
};
use sha2::{Digest as ShaDigest, Sha256};

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_RS_PW: u32 = 0x4000_0009;
const TPMA_SESSION_CONTINUESESSION: u8 = 1;

const TPM_CC_NV_INCREMENT: u32 = 0x0000_0134;
const TPM_CC_NV_WRITE: u32 = 0x0000_0137;
const TPM_CC_STARTUP: u32 = 0x0000_0144;
const TPM_CC_NV_READ: u32 = 0x0000_014e;
const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;

const TPM_RC_SUCCESS: u32 = 0;
const TPM_RC_INITIALIZE: u32 = 0x0000_0100;
const TPM_SU_CLEAR: u16 = 0;
const TPM_ALG_SHA256: u16 = 0x000b;

const TPMA_NV_AUTHWRITE: u32 = 1 << 2;
const TPMA_NV_COUNTER: u32 = 1 << 4;
const TPMA_NV_POLICY_DELETE: u32 = 1 << 10;
const TPMA_NV_WRITEALL: u32 = 1 << 12;
const TPMA_NV_AUTHREAD: u32 = 1 << 18;
const TPMA_NV_NO_DA: u32 = 1 << 25;
const TPMA_NV_ORDERLY: u32 = 1 << 26;
const TPMA_NV_WRITELOCKED: u32 = 1 << 11;
const TPMA_NV_READLOCKED: u32 = 1 << 28;
const TPMA_NV_WRITTEN: u32 = 1 << 29;
const TPMA_NV_PLATFORMCREATE: u32 = 1 << 30;
const TPMA_NV_TYPE_MASK: u32 = 0x0f << 4;

const COUNTER_ATTRIBUTES: u32 = TPMA_NV_AUTHWRITE
    | TPMA_NV_COUNTER
    | TPMA_NV_POLICY_DELETE
    | TPMA_NV_AUTHREAD
    | TPMA_NV_NO_DA
    | TPMA_NV_PLATFORMCREATE;
const SLOT_ATTRIBUTES: u32 = TPMA_NV_AUTHWRITE
    | TPMA_NV_POLICY_DELETE
    | TPMA_NV_WRITEALL
    | TPMA_NV_AUTHREAD
    | TPMA_NV_NO_DA
    | TPMA_NV_PLATFORMCREATE;

// SHA256 trial-policy digest for PolicyCommandCode(TPM2_NV_Read).  It permits
// no write operation and, crucially, cannot satisfy the ADMIN-role
// TPM2_NV_UndefineSpaceSpecial command selected by TPMA_NV_POLICY_DELETE.
const IMMUTABLE_DELETE_POLICY: [u8; 32] = [
    0x47, 0xce, 0x30, 0x32, 0xd8, 0xba, 0xd1, 0xf3, 0x08, 0x9c, 0xb0, 0xc0, 0x90, 0x88, 0xde, 0x43,
    0x50, 0x14, 0x91, 0xd4, 0x60, 0x40, 0x2b, 0x90, 0xcd, 0x1b, 0x7f, 0xc0, 0xb6, 0x8c, 0xa9, 0x2f,
];

const TPM_TIS_BASE: usize = 0xfed4_0000;
const TPM_TIS_LOCALITY_SIZE: usize = 0x1000;
const TIS_ACCESS: usize = 0x0000;
const TIS_STS: usize = 0x0018;
const TIS_DATA_FIFO: usize = 0x0024;
const TIS_DID_VID: usize = 0x0f00;

const TIS_ACCESS_VALID: u8 = 1 << 7;
const TIS_ACCESS_ACTIVE_LOCALITY: u8 = 1 << 5;
const TIS_ACCESS_REQUEST_USE: u8 = 1 << 1;
const TIS_ACCESS_RELINQUISH: u8 = 1 << 5;

const TIS_STS_VALID: u32 = 1 << 7;
const TIS_STS_COMMAND_READY: u8 = 1 << 6;
const TIS_STS_GO: u8 = 1 << 5;
const TIS_STS_DATA_AVAIL: u32 = 1 << 4;
const TIS_STS_EXPECT: u32 = 1 << 3;

const TPM_HEADER_LEN: usize = 10;
const MAX_TPM_COMMAND: usize = 4096;
const MAX_TPM_RESPONSE: usize = 4096;
const DEFAULT_POLL_BUDGET: u32 = 20_000_000;
// Every fixture index has nameAlg=SHA256, so TPM2B_AUTH cannot exceed that
// algorithm's 32-byte digest size.
const MAX_INDEX_AUTH: usize = 32;

const SLOT_MAGIC: [u8; 8] = *b"CSERTPM1";
const SLOT_VERSION: u16 = 1;
const SLOT_KIND_TIP: u8 = 1;
const SLOT_KIND_LEASE: u8 = 2;
const SLOT_PREFIX_LEN: usize = 20;
const TIP_BODY_LEN: usize = 148;
const TIP_SLOT_LEN: usize = TIP_BODY_LEN + 32;
const LEASE_BODY_LEN: usize = 108;
const LEASE_SLOT_LEN: usize = LEASE_BODY_LEN + 32;

// TPM2 ordinary NV has no compare-and-swap command. The double-slot selector
// protocol is atomic only under one writer, so construction acquires a
// boot-lifetime Nexus provider lease. This is not an advisory optimization:
// a second provider instance is rejected before it can issue any TPM command.
// Physical deployments must also keep all raw access to these six indices
// outside untrusted/runtime principals.
static TPM_NV_PROVIDER_OWNED: AtomicBool = AtomicBool::new(false);

struct ExclusiveProviderLease;

impl ExclusiveProviderLease {
    fn acquire<E>() -> Result<Self, TpmNvAnchorError<E>> {
        TPM_NV_PROVIDER_OWNED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| TpmNvAnchorError::ProviderAlreadyOpen)?;
        Ok(Self)
    }
}

impl Drop for ExclusiveProviderLease {
    fn drop(&mut self) {
        TPM_NV_PROVIDER_OWNED.store(false, Ordering::Release);
    }
}

/// Six pre-provisioned TPM2 NV indices used by one CSER Registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TpmNvLayout {
    tip_counter: u32,
    tip_slots: [u32; 2],
    lease_counter: u32,
    lease_slots: [u32; 2],
}

impl TpmNvLayout {
    /// Fixed development layout used by the QEMU/swtpm fixture.
    ///
    /// Production provisioning should allocate a platform-owned range and
    /// pass the exact resulting layout instead.
    pub(crate) const fn qemu_fixture() -> Self {
        Self {
            tip_counter: 0x0180_0100,
            tip_slots: [0x0180_0101, 0x0180_0102],
            lease_counter: 0x0180_0103,
            lease_slots: [0x0180_0104, 0x0180_0105],
        }
    }

    fn all_indices(self) -> [u32; 6] {
        [
            self.tip_counter,
            self.tip_slots[0],
            self.tip_slots[1],
            self.lease_counter,
            self.lease_slots[0],
            self.lease_slots[1],
        ]
    }
}

/// Password authorization for the pre-provisioned runtime NV indices.
///
/// This value authorizes reads, writes, and increments only.  It is not the
/// owner/platform hierarchy authorization used to create, delete, or clear the
/// indices.
pub(crate) struct TpmNvIndexAuth {
    bytes: [u8; MAX_INDEX_AUTH],
    len: u8,
}

impl TpmNvIndexAuth {
    pub(crate) fn new(bytes: &[u8]) -> Result<Self, TpmNvAuthError> {
        if bytes.len() > MAX_INDEX_AUTH {
            return Err(TpmNvAuthError::TooLong);
        }
        let mut value = Self {
            bytes: [0; MAX_INDEX_AUTH],
            len: u8::try_from(bytes.len()).map_err(|_| TpmNvAuthError::TooLong)?,
        };
        value.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(value)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl Drop for TpmNvIndexAuth {
    fn drop(&mut self) {
        self.bytes.fill(0);
        self.len = 0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TpmNvAuthError {
    TooLong,
}

/// Public metadata returned by `TPM2_NV_ReadPublic`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TpmNvPublic {
    index: u32,
    name_algorithm: u16,
    attributes: u32,
    authorization_policy: [u8; 32],
    data_size: u16,
}

/// Minimal TPM2 NV command transport consumed by the selector protocol.
///
/// Each method represents exactly one TPM command.  In particular,
/// `write_exact` must not split one slot across multiple `TPM2_NV_Write`
/// commands.
pub(crate) trait TpmNvTransport {
    type Error;

    fn read_public(&mut self, index: u32) -> Result<TpmNvPublic, Self::Error>;

    fn read_exact(
        &mut self,
        index: u32,
        auth: &TpmNvIndexAuth,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;

    fn write_exact(
        &mut self,
        index: u32,
        auth: &TpmNvIndexAuth,
        input: &[u8],
    ) -> Result<(), Self::Error>;

    fn increment(&mut self, index: u32, auth: &TpmNvIndexAuth) -> Result<(), Self::Error>;
}

/// Failure from the double-slot trusted-anchor protocol.
#[derive(Debug)]
pub(crate) enum TpmNvAnchorError<E> {
    Transport(E),
    ProviderAlreadyOpen,
    IndexSetContainsDuplicates,
    UnexpectedIndexPublic {
        index: u32,
        observed_attributes: u32,
        observed_size: u16,
    },
    CorruptSelectedSlot {
        index: u32,
    },
    CounterOverflow {
        index: u32,
    },
    CounterDidNotAdvance {
        index: u32,
        expected: u64,
        observed: u64,
    },
    Protocol(PersistenceProtocolError),
}

impl<E> From<PersistenceProtocolError> for TpmNvAnchorError<E> {
    fn from(error: PersistenceProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// TPM2 NV implementation of the portable core's trusted-anchor backend.
///
/// Construction validates the exact public attributes and selected state of
/// all indices and acquires the boot-lifetime single-writer provider lease.
/// Every operation re-reads both counters and selected slots so stale, corrupt,
/// or mismatched state fails closed.
pub(crate) struct TpmNvTrustedAnchor<T> {
    transport: Option<T>,
    layout: TpmNvLayout,
    auth: TpmNvIndexAuth,
    expected_binding: RecoveryBinding,
    tip_sequence: u64,
    lease_sequence: u64,
    committed: TrustedAnchorSnapshot,
    issued: Freshness,
    _exclusive: ExclusiveProviderLease,
}

impl<T> TpmNvTrustedAnchor<T>
where
    T: TpmNvTransport,
{
    pub(crate) fn open(
        mut transport: T,
        layout: TpmNvLayout,
        auth: TpmNvIndexAuth,
        expected_binding: RecoveryBinding,
    ) -> Result<Self, TpmNvAnchorError<T::Error>> {
        let exclusive = ExclusiveProviderLease::acquire()?;
        validate_unique_indices(layout)?;
        validate_index_publics(&mut transport, layout)?;
        let (tip_sequence, committed) = read_selected_tip(&mut transport, layout, &auth)?;
        let (lease_sequence, issued) = read_selected_lease(&mut transport, layout, &auth)?;
        validate_loaded_state(expected_binding, committed, issued)?;
        Ok(Self {
            transport: Some(transport),
            layout,
            auth,
            expected_binding,
            tip_sequence,
            lease_sequence,
            committed,
            issued,
            _exclusive: exclusive,
        })
    }

    pub(crate) const fn committed(&self) -> TrustedAnchorSnapshot {
        self.committed
    }

    fn transport_mut(&mut self) -> &mut T {
        self.transport
            .as_mut()
            .expect("live TPM NV provider retains its transport")
    }

    #[cfg(ktest)]
    fn into_transport(mut self) -> T {
        self.transport
            .take()
            .expect("live TPM NV provider retains its transport")
    }

    fn refresh(&mut self) -> Result<(), TpmNvAnchorError<T::Error>> {
        let transport = self
            .transport
            .as_mut()
            .expect("live TPM NV provider retains its transport");
        validate_index_publics(transport, self.layout)?;
        let (tip_sequence, committed) = read_selected_tip(transport, self.layout, &self.auth)?;
        let (lease_sequence, issued) = read_selected_lease(transport, self.layout, &self.auth)?;
        validate_loaded_state(self.expected_binding, committed, issued)?;
        self.tip_sequence = tip_sequence;
        self.lease_sequence = lease_sequence;
        self.committed = committed;
        self.issued = issued;
        Ok(())
    }

    fn write_verified_slot(
        &mut self,
        index: u32,
        bytes: &[u8],
    ) -> Result<(), TpmNvAnchorError<T::Error>> {
        self.transport
            .as_mut()
            .expect("live TPM NV provider retains its transport")
            .write_exact(index, &self.auth, bytes)
            .map_err(TpmNvAnchorError::Transport)?;
        let mut observed = Vec::new();
        observed.resize(bytes.len(), 0);
        self.transport
            .as_mut()
            .expect("live TPM NV provider retains its transport")
            .read_exact(index, &self.auth, &mut observed)
            .map_err(TpmNvAnchorError::Transport)?;
        if observed != bytes {
            return Err(TpmNvAnchorError::CorruptSelectedSlot { index });
        }
        Ok(())
    }

    fn increment_and_verify(
        &mut self,
        counter_index: u32,
        expected: u64,
    ) -> Result<(), TpmNvAnchorError<T::Error>> {
        self.transport
            .as_mut()
            .expect("live TPM NV provider retains its transport")
            .increment(counter_index, &self.auth)
            .map_err(TpmNvAnchorError::Transport)?;
        let observed = read_counter(
            self.transport
                .as_mut()
                .expect("live TPM NV provider retains its transport"),
            counter_index,
            &self.auth,
        )?;
        if observed != expected {
            return Err(TpmNvAnchorError::CounterDidNotAdvance {
                index: counter_index,
                expected,
                observed,
            });
        }
        Ok(())
    }
}

impl<T> TrustedAnchorBackend for TpmNvTrustedAnchor<T>
where
    T: TpmNvTransport,
{
    type Error = TpmNvAnchorError<T::Error>;

    fn reserve_recovery_epoch(
        &mut self,
        binding: RecoveryBinding,
        observed_device: DeviceGeneration,
    ) -> Result<RecoveryLease, Self::Error> {
        self.refresh()?;
        if binding != self.expected_binding || binding != self.committed.binding() {
            return Err(PersistenceProtocolError::BindingMismatch.into());
        }
        if observed_device.get() < self.committed.committed_freshness().device().get()
            || observed_device.get() < self.issued.device().get()
        {
            return Err(PersistenceProtocolError::StaleFreshness.into());
        }

        let next_boot = next_boot(self.issued)?;
        let next_journal = next_journal(self.issued)?;
        let next = Freshness::new(
            next_boot,
            binding.registry(),
            binding.binding(),
            observed_device,
            next_journal,
        )
        .map_err(|_| PersistenceProtocolError::InvalidAnchor)?;
        let next_sequence =
            self.lease_sequence
                .checked_add(1)
                .ok_or(TpmNvAnchorError::CounterOverflow {
                    index: self.layout.lease_counter,
                })?;
        let slot = slot_for_sequence(self.layout.lease_slots, next_sequence);
        let encoded = encode_lease_slot(next_sequence, binding, next);

        self.write_verified_slot(slot, &encoded)?;
        self.increment_and_verify(self.layout.lease_counter, next_sequence)?;
        self.lease_sequence = next_sequence;
        self.issued = next;
        RecoveryLease::from_trusted_backend(self.committed, next).map_err(Into::into)
    }

    fn compare_and_advance(
        &mut self,
        expected: TrustedAnchorSnapshot,
        replacement: TrustedAnchorSnapshot,
    ) -> Result<(), Self::Error> {
        self.refresh()?;
        if expected != self.committed {
            return Err(PersistenceProtocolError::StaleJournalHead.into());
        }
        validate_replacement(expected, replacement, self.issued)?;

        let next_sequence =
            self.tip_sequence
                .checked_add(1)
                .ok_or(TpmNvAnchorError::CounterOverflow {
                    index: self.layout.tip_counter,
                })?;
        let slot = slot_for_sequence(self.layout.tip_slots, next_sequence);
        let encoded = encode_tip_slot(next_sequence, replacement);

        self.write_verified_slot(slot, &encoded)?;
        self.increment_and_verify(self.layout.tip_counter, next_sequence)?;
        self.tip_sequence = next_sequence;
        self.committed = replacement;
        Ok(())
    }
}

fn validate_unique_indices<E>(layout: TpmNvLayout) -> Result<(), TpmNvAnchorError<E>> {
    let indices = layout.all_indices();
    for left in 0..indices.len() {
        for right in (left + 1)..indices.len() {
            if indices[left] == indices[right] {
                return Err(TpmNvAnchorError::IndexSetContainsDuplicates);
            }
        }
    }
    Ok(())
}

fn validate_index_publics<T>(
    transport: &mut T,
    layout: TpmNvLayout,
) -> Result<(), TpmNvAnchorError<T::Error>>
where
    T: TpmNvTransport,
{
    validate_index_public(transport, layout.tip_counter, COUNTER_ATTRIBUTES, 8)?;
    for index in layout.tip_slots {
        validate_index_public(
            transport,
            index,
            SLOT_ATTRIBUTES,
            u16::try_from(TIP_SLOT_LEN).expect("tip slot length fits u16"),
        )?;
    }
    validate_index_public(transport, layout.lease_counter, COUNTER_ATTRIBUTES, 8)?;
    for index in layout.lease_slots {
        validate_index_public(
            transport,
            index,
            SLOT_ATTRIBUTES,
            u16::try_from(LEASE_SLOT_LEN).expect("lease slot length fits u16"),
        )?;
    }
    Ok(())
}

fn validate_index_public<T>(
    transport: &mut T,
    index: u32,
    expected_attributes: u32,
    expected_size: u16,
) -> Result<(), TpmNvAnchorError<T::Error>>
where
    T: TpmNvTransport,
{
    let public = transport
        .read_public(index)
        .map_err(TpmNvAnchorError::Transport)?;
    let stable_attributes = public.attributes & !TPMA_NV_WRITTEN;
    if public.index != index
        || public.name_algorithm != TPM_ALG_SHA256
        || stable_attributes != expected_attributes
        || public.authorization_policy != IMMUTABLE_DELETE_POLICY
        || public.data_size != expected_size
        || public.attributes & (TPMA_NV_ORDERLY | TPMA_NV_WRITELOCKED | TPMA_NV_READLOCKED) != 0
    {
        return Err(TpmNvAnchorError::UnexpectedIndexPublic {
            index,
            observed_attributes: public.attributes,
            observed_size: public.data_size,
        });
    }
    Ok(())
}

fn validate_loaded_state<E>(
    expected_binding: RecoveryBinding,
    committed: TrustedAnchorSnapshot,
    issued: Freshness,
) -> Result<(), TpmNvAnchorError<E>> {
    if committed.binding() != expected_binding
        || issued.registry().get() != expected_binding.registry().get()
        || issued.binding() != expected_binding.binding()
    {
        return Err(PersistenceProtocolError::BindingMismatch.into());
    }
    let committed_freshness = committed.committed_freshness();
    if issued.boot().get() < committed_freshness.boot().get()
        || issued.journal().get() < committed_freshness.journal().get()
        || issued.device().get() < committed_freshness.device().get()
    {
        return Err(PersistenceProtocolError::StaleFreshness.into());
    }
    Ok(())
}

fn validate_replacement<E>(
    expected: TrustedAnchorSnapshot,
    replacement: TrustedAnchorSnapshot,
    issued: Freshness,
) -> Result<(), TpmNvAnchorError<E>> {
    let expected_freshness = expected.committed_freshness();
    let replacement_freshness = replacement.committed_freshness();
    if replacement.binding() != expected.binding()
        || expected.revision().checked_add(1) != Some(replacement.revision())
        || replacement_freshness.boot().get() < expected_freshness.boot().get()
        || replacement_freshness.journal().get() < expected_freshness.journal().get()
        || replacement_freshness.device().get() < expected_freshness.device().get()
        || (replacement_freshness != expected_freshness && replacement_freshness != issued)
    {
        return Err(PersistenceProtocolError::StaleFreshness.into());
    }
    Ok(())
}

fn next_boot<E>(freshness: Freshness) -> Result<BootGeneration, TpmNvAnchorError<E>> {
    let value = freshness
        .boot()
        .get()
        .checked_add(1)
        .ok_or(PersistenceProtocolError::StaleFreshness)?;
    BootGeneration::new(value).map_err(|_| PersistenceProtocolError::StaleFreshness.into())
}

fn next_journal<E>(freshness: Freshness) -> Result<JournalGeneration, TpmNvAnchorError<E>> {
    let value = freshness
        .journal()
        .get()
        .checked_add(1)
        .ok_or(PersistenceProtocolError::StaleFreshness)?;
    JournalGeneration::new(value).map_err(|_| PersistenceProtocolError::StaleFreshness.into())
}

fn slot_for_sequence(slots: [u32; 2], sequence: u64) -> u32 {
    slots[usize::try_from(sequence & 1).expect("slot selector is zero or one")]
}

fn read_counter<T>(
    transport: &mut T,
    index: u32,
    auth: &TpmNvIndexAuth,
) -> Result<u64, TpmNvAnchorError<T::Error>>
where
    T: TpmNvTransport,
{
    let mut bytes = [0; 8];
    transport
        .read_exact(index, auth, &mut bytes)
        .map_err(TpmNvAnchorError::Transport)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_selected_tip<T>(
    transport: &mut T,
    layout: TpmNvLayout,
    auth: &TpmNvIndexAuth,
) -> Result<(u64, TrustedAnchorSnapshot), TpmNvAnchorError<T::Error>>
where
    T: TpmNvTransport,
{
    let sequence = read_counter(transport, layout.tip_counter, auth)?;
    let index = slot_for_sequence(layout.tip_slots, sequence);
    let mut bytes = [0; TIP_SLOT_LEN];
    transport
        .read_exact(index, auth, &mut bytes)
        .map_err(TpmNvAnchorError::Transport)?;
    let snapshot =
        decode_tip_slot(&bytes, sequence).ok_or(TpmNvAnchorError::CorruptSelectedSlot { index })?;
    Ok((sequence, snapshot))
}

fn read_selected_lease<T>(
    transport: &mut T,
    layout: TpmNvLayout,
    auth: &TpmNvIndexAuth,
) -> Result<(u64, Freshness), TpmNvAnchorError<T::Error>>
where
    T: TpmNvTransport,
{
    let sequence = read_counter(transport, layout.lease_counter, auth)?;
    let index = slot_for_sequence(layout.lease_slots, sequence);
    let mut bytes = [0; LEASE_SLOT_LEN];
    transport
        .read_exact(index, auth, &mut bytes)
        .map_err(TpmNvAnchorError::Transport)?;
    let (_, issued) = decode_lease_slot(&bytes, sequence)
        .ok_or(TpmNvAnchorError::CorruptSelectedSlot { index })?;
    Ok((sequence, issued))
}

fn encode_tip_slot(sequence: u64, snapshot: TrustedAnchorSnapshot) -> [u8; TIP_SLOT_LEN] {
    let mut bytes = [0; TIP_SLOT_LEN];
    encode_slot_prefix(&mut bytes, SLOT_KIND_TIP, sequence);
    let mut cursor = SLOT_PREFIX_LEN;
    encode_binding(&mut bytes, &mut cursor, snapshot.binding());
    encode_freshness(&mut bytes, &mut cursor, snapshot.committed_freshness());
    put_u64(&mut bytes, &mut cursor, snapshot.revision());
    put_bytes(&mut bytes, &mut cursor, &snapshot.head().bytes());
    debug_assert_eq!(cursor, TIP_BODY_LEN);
    finish_checksum(&mut bytes, TIP_BODY_LEN);
    bytes
}

fn decode_tip_slot(
    bytes: &[u8; TIP_SLOT_LEN],
    expected_sequence: u64,
) -> Option<TrustedAnchorSnapshot> {
    if !validate_slot_prefix_and_checksum(bytes, SLOT_KIND_TIP, expected_sequence, TIP_BODY_LEN) {
        return None;
    }
    let mut cursor = SLOT_PREFIX_LEN;
    let binding = decode_binding(bytes, &mut cursor)?;
    let freshness = decode_freshness(bytes, &mut cursor)?;
    let revision = take_u64(bytes, &mut cursor)?;
    let head = Digest::new(take_array::<32>(bytes, &mut cursor)?);
    if cursor != TIP_BODY_LEN {
        return None;
    }
    TrustedAnchorSnapshot::from_trusted_backend(binding, freshness, revision, head).ok()
}

fn encode_lease_slot(
    sequence: u64,
    binding: RecoveryBinding,
    issued: Freshness,
) -> [u8; LEASE_SLOT_LEN] {
    let mut bytes = [0; LEASE_SLOT_LEN];
    encode_slot_prefix(&mut bytes, SLOT_KIND_LEASE, sequence);
    let mut cursor = SLOT_PREFIX_LEN;
    encode_binding(&mut bytes, &mut cursor, binding);
    encode_freshness(&mut bytes, &mut cursor, issued);
    debug_assert_eq!(cursor, LEASE_BODY_LEN);
    finish_checksum(&mut bytes, LEASE_BODY_LEN);
    bytes
}

fn decode_lease_slot(
    bytes: &[u8; LEASE_SLOT_LEN],
    expected_sequence: u64,
) -> Option<(RecoveryBinding, Freshness)> {
    if !validate_slot_prefix_and_checksum(bytes, SLOT_KIND_LEASE, expected_sequence, LEASE_BODY_LEN)
    {
        return None;
    }
    let mut cursor = SLOT_PREFIX_LEN;
    let binding = decode_binding(bytes, &mut cursor)?;
    let freshness = decode_freshness(bytes, &mut cursor)?;
    if cursor != LEASE_BODY_LEN
        || freshness.registry().get() != binding.registry().get()
        || freshness.binding() != binding.binding()
    {
        return None;
    }
    Some((binding, freshness))
}

fn encode_slot_prefix(bytes: &mut [u8], kind: u8, sequence: u64) {
    bytes[..8].copy_from_slice(&SLOT_MAGIC);
    bytes[8..10].copy_from_slice(&SLOT_VERSION.to_be_bytes());
    bytes[10] = kind;
    bytes[11] = 0;
    bytes[12..20].copy_from_slice(&sequence.to_be_bytes());
}

fn validate_slot_prefix_and_checksum(
    bytes: &[u8],
    kind: u8,
    expected_sequence: u64,
    body_len: usize,
) -> bool {
    if bytes.len() != body_len + 32
        || bytes[..8] != SLOT_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != SLOT_VERSION
        || bytes[10] != kind
        || bytes[11] != 0
        || u64::from_be_bytes(bytes[12..20].try_into().expect("fixed slot sequence slice"))
            != expected_sequence
    {
        return false;
    }
    let digest = Sha256::digest(&bytes[..body_len]);
    digest.as_slice() == &bytes[body_len..]
}

fn finish_checksum(bytes: &mut [u8], body_len: usize) {
    let digest = Sha256::digest(&bytes[..body_len]);
    bytes[body_len..].copy_from_slice(&digest);
}

fn encode_binding(bytes: &mut [u8], cursor: &mut usize, binding: RecoveryBinding) {
    put_bytes(bytes, cursor, &binding.catalog_digest().bytes());
    put_u64(bytes, cursor, binding.registry().get());
    put_u64(bytes, cursor, binding.binding());
}

fn decode_binding(bytes: &[u8], cursor: &mut usize) -> Option<RecoveryBinding> {
    let catalog = Digest::new(take_array::<32>(bytes, cursor)?);
    let registry = RegistryInstance::new(take_u64(bytes, cursor)?).ok()?;
    let binding = take_u64(bytes, cursor)?;
    RecoveryBinding::new(catalog, registry, binding).ok()
}

fn encode_freshness(bytes: &mut [u8], cursor: &mut usize, freshness: Freshness) {
    put_u64(bytes, cursor, freshness.boot().get());
    put_u64(bytes, cursor, freshness.registry().get());
    put_u64(bytes, cursor, freshness.binding());
    put_u64(bytes, cursor, freshness.device().get());
    put_u64(bytes, cursor, freshness.journal().get());
}

fn decode_freshness(bytes: &[u8], cursor: &mut usize) -> Option<Freshness> {
    let boot = BootGeneration::new(take_u64(bytes, cursor)?).ok()?;
    let registry = RegistryInstance::new(take_u64(bytes, cursor)?).ok()?;
    let binding = take_u64(bytes, cursor)?;
    let device = DeviceGeneration::new(take_u64(bytes, cursor)?).ok()?;
    let journal = JournalGeneration::new(take_u64(bytes, cursor)?).ok()?;
    Freshness::new(boot, registry, binding, device, journal).ok()
}

fn put_u64(bytes: &mut [u8], cursor: &mut usize, value: u64) {
    put_bytes(bytes, cursor, &value.to_be_bytes());
}

fn put_bytes(bytes: &mut [u8], cursor: &mut usize, value: &[u8]) {
    let end = cursor
        .checked_add(value.len())
        .expect("fixed slot cursor overflow");
    bytes[*cursor..end].copy_from_slice(value);
    *cursor = end;
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    Some(u64::from_be_bytes(take_array::<8>(bytes, cursor)?))
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Option<[u8; N]> {
    let end = cursor.checked_add(N)?;
    let value = bytes.get(*cursor..end)?.try_into().ok()?;
    *cursor = end;
    Some(value)
}

/// Polling TPM2 TIS locality-zero command transport for QEMU `tpm-tis`.
///
/// The fixed address is the QEMU q35/PC TIS aperture.  A physical platform
/// integration must discover and validate the interface using ACPI TPM2/SSDT
/// data before calling an equivalent constructor.
pub(crate) struct QemuTisTpm2 {
    mmio: IoMem,
    poll_budget: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TisTpmError {
    MmioUnavailable,
    DeviceAbsent,
    LocalityTimeout,
    CommandReadyTimeout,
    BurstTimeout,
    ExpectMismatch,
    ResponseTimeout,
    CommandTooLarge,
    ResponseTooLarge,
    MalformedResponse,
    TpmResponse(u32),
    NvBufferTooLarge,
}

impl QemuTisTpm2 {
    pub(crate) fn acquire_qemu_fixture() -> Result<Self, TisTpmError> {
        let mmio = IoMem::acquire(TPM_TIS_BASE..TPM_TIS_BASE + TPM_TIS_LOCALITY_SIZE)
            .map_err(|_| TisTpmError::MmioUnavailable)?;
        let mut transport = Self {
            mmio,
            poll_budget: DEFAULT_POLL_BUDGET,
        };
        let did_vid = transport
            .mmio
            .read_once::<u32>(TIS_DID_VID)
            .map_err(|_| TisTpmError::DeviceAbsent)?;
        if did_vid == 0 || did_vid == u32::MAX {
            return Err(TisTpmError::DeviceAbsent);
        }
        transport.claim_locality()?;
        transport.startup_clear_for_qemu_fixture()?;
        Ok(transport)
    }

    fn claim_locality(&mut self) -> Result<(), TisTpmError> {
        let access = self.read_u8(TIS_ACCESS)?;
        if access & TIS_ACCESS_VALID == 0 {
            return Err(TisTpmError::DeviceAbsent);
        }
        if access & TIS_ACCESS_ACTIVE_LOCALITY == 0 {
            self.write_u8(TIS_ACCESS, TIS_ACCESS_REQUEST_USE)?;
            self.poll_access(TIS_ACCESS_ACTIVE_LOCALITY)?;
        }
        Ok(())
    }

    fn poll_access(&self, required: u8) -> Result<u8, TisTpmError> {
        for _ in 0..self.poll_budget {
            let value = self.read_u8(TIS_ACCESS)?;
            if value & TIS_ACCESS_VALID != 0 && value & required == required {
                return Ok(value);
            }
            spin_loop();
        }
        Err(TisTpmError::LocalityTimeout)
    }

    fn poll_status(&self, required: u32, timeout: TisTpmError) -> Result<u32, TisTpmError> {
        for _ in 0..self.poll_budget {
            let value = self.read_status()?;
            if value & required == required {
                return Ok(value);
            }
            spin_loop();
        }
        Err(timeout)
    }

    fn wait_burst(&self) -> Result<usize, TisTpmError> {
        for _ in 0..self.poll_budget {
            let status = self.read_status()?;
            let burst =
                usize::try_from((status >> 8) & 0xffff).expect("16-bit burst count fits usize");
            if burst != 0 {
                return Ok(burst);
            }
            spin_loop();
        }
        Err(TisTpmError::BurstTimeout)
    }

    fn execute(&mut self, command: &[u8]) -> Result<Vec<u8>, TisTpmError> {
        if command.len() < TPM_HEADER_LEN || command.len() > MAX_TPM_COMMAND {
            return Err(TisTpmError::CommandTooLarge);
        }
        self.claim_locality()?;
        self.write_u8(TIS_STS, TIS_STS_COMMAND_READY)?;
        self.poll_status(
            u32::from(TIS_STS_COMMAND_READY),
            TisTpmError::CommandReadyTimeout,
        )?;

        let mut written = 0;
        while written < command.len() {
            let burst = self.wait_burst()?;
            let count = burst.min(command.len() - written);
            for byte in &command[written..written + count] {
                self.write_u8(TIS_DATA_FIFO, *byte)?;
            }
            written += count;
            let status = self.read_status()?;
            let expects_more = written < command.len();
            if (status & TIS_STS_EXPECT != 0) != expects_more {
                self.write_u8(TIS_STS, TIS_STS_COMMAND_READY)?;
                return Err(TisTpmError::ExpectMismatch);
            }
        }

        self.write_u8(TIS_STS, TIS_STS_GO)?;
        self.poll_status(
            TIS_STS_VALID | TIS_STS_DATA_AVAIL,
            TisTpmError::ResponseTimeout,
        )?;

        let mut response = Vec::new();
        response.reserve(TPM_HEADER_LEN);
        self.read_fifo_exact(&mut response, TPM_HEADER_LEN)?;
        let response_size = usize::try_from(u32::from_be_bytes(
            response[2..6].try_into().expect("TPM response size header"),
        ))
        .map_err(|_| TisTpmError::ResponseTooLarge)?;
        if !(TPM_HEADER_LEN..=MAX_TPM_RESPONSE).contains(&response_size) {
            self.write_u8(TIS_STS, TIS_STS_COMMAND_READY)?;
            return Err(TisTpmError::ResponseTooLarge);
        }
        self.read_fifo_exact(&mut response, response_size - TPM_HEADER_LEN)?;
        let status = self.read_status()?;
        self.write_u8(TIS_STS, TIS_STS_COMMAND_READY)?;
        if status & TIS_STS_DATA_AVAIL != 0 {
            return Err(TisTpmError::MalformedResponse);
        }
        Ok(response)
    }

    fn read_fifo_exact(&self, output: &mut Vec<u8>, length: usize) -> Result<(), TisTpmError> {
        let target = output
            .len()
            .checked_add(length)
            .ok_or(TisTpmError::ResponseTooLarge)?;
        output.reserve(length);
        while output.len() < target {
            let burst = self.wait_burst()?;
            let count = burst.min(target - output.len());
            for _ in 0..count {
                output.push(self.read_u8(TIS_DATA_FIFO)?);
            }
        }
        Ok(())
    }

    fn execute_success(&mut self, command: &[u8]) -> Result<Vec<u8>, TisTpmError> {
        let response = self.execute(command)?;
        if response.len() < TPM_HEADER_LEN {
            return Err(TisTpmError::MalformedResponse);
        }
        let declared = usize::try_from(u32::from_be_bytes(
            response[2..6].try_into().expect("TPM response header"),
        ))
        .map_err(|_| TisTpmError::MalformedResponse)?;
        if declared != response.len() {
            return Err(TisTpmError::MalformedResponse);
        }
        let response_code =
            u32::from_be_bytes(response[6..10].try_into().expect("TPM response code"));
        if response_code != TPM_RC_SUCCESS {
            return Err(TisTpmError::TpmResponse(response_code));
        }
        Ok(response)
    }

    /// Bring up the emulated TPM after QEMU's control-channel INIT.
    ///
    /// OVMF does not guarantee that the TPM remains started when QEMU resets
    /// the swtpm backend during handoff.  The fixture therefore performs the
    /// architecturally required TPM2_Startup(CLEAR) before issuing NV
    /// commands.  `TPM_RC_INITIALIZE` means firmware already performed the
    /// one permitted Startup for this reset and is accepted as an
    /// already-started state.  A physical platform must instead integrate
    /// with its firmware/ACPI TPM lifecycle and must not blindly choose CLEAR.
    fn startup_clear_for_qemu_fixture(&mut self) -> Result<(), TisTpmError> {
        let mut command = command_header(TPM_ST_NO_SESSIONS, TPM_CC_STARTUP);
        push_u16(&mut command, TPM_SU_CLEAR);
        finish_command_size(&mut command)?;
        let response = self.execute(&command)?;
        if response.len() != TPM_HEADER_LEN
            || u16::from_be_bytes(response[..2].try_into().expect("TPM response tag"))
                != TPM_ST_NO_SESSIONS
            || usize::try_from(u32::from_be_bytes(
                response[2..6].try_into().expect("TPM response size"),
            ))
            .map_err(|_| TisTpmError::MalformedResponse)?
                != TPM_HEADER_LEN
        {
            return Err(TisTpmError::MalformedResponse);
        }
        let response_code =
            u32::from_be_bytes(response[6..10].try_into().expect("TPM response code"));
        match response_code {
            TPM_RC_SUCCESS | TPM_RC_INITIALIZE => Ok(()),
            code => Err(TisTpmError::TpmResponse(code)),
        }
    }

    fn read_u8(&self, offset: usize) -> Result<u8, TisTpmError> {
        self.mmio
            .read_once::<u8>(offset)
            .map_err(|_| TisTpmError::DeviceAbsent)
    }

    fn write_u8(&self, offset: usize, value: u8) -> Result<(), TisTpmError> {
        self.mmio
            .write_once(offset, &value)
            .map_err(|_| TisTpmError::DeviceAbsent)
    }

    fn read_status(&self) -> Result<u32, TisTpmError> {
        self.mmio
            .read_once::<u32>(TIS_STS)
            .map_err(|_| TisTpmError::DeviceAbsent)
    }
}

impl Drop for QemuTisTpm2 {
    fn drop(&mut self) {
        let _ = self.write_u8(TIS_ACCESS, TIS_ACCESS_RELINQUISH);
    }
}

impl TpmNvTransport for QemuTisTpm2 {
    type Error = TisTpmError;

    fn read_public(&mut self, index: u32) -> Result<TpmNvPublic, Self::Error> {
        let mut command = command_header(TPM_ST_NO_SESSIONS, TPM_CC_NV_READ_PUBLIC);
        push_u32(&mut command, index);
        finish_command_size(&mut command)?;
        let response = self.execute_success(&command)?;
        parse_nv_public(&response)
    }

    fn read_exact(
        &mut self,
        index: u32,
        auth: &TpmNvIndexAuth,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        let size = u16::try_from(output.len()).map_err(|_| TisTpmError::NvBufferTooLarge)?;
        let mut command = command_header(TPM_ST_SESSIONS, TPM_CC_NV_READ);
        push_u32(&mut command, index);
        push_u32(&mut command, index);
        push_password_session(&mut command, auth)?;
        push_u16(&mut command, size);
        push_u16(&mut command, 0);
        finish_command_size(&mut command)?;
        let response = self.execute_success(&command)?;
        let parameters = response_parameters(&response)?;
        if parameters.len() != output.len() + 2
            || u16::from_be_bytes(parameters[..2].try_into().expect("TPM2B NV size")) != size
        {
            return Err(TisTpmError::MalformedResponse);
        }
        output.copy_from_slice(&parameters[2..]);
        Ok(())
    }

    fn write_exact(
        &mut self,
        index: u32,
        auth: &TpmNvIndexAuth,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        let size = u16::try_from(input.len()).map_err(|_| TisTpmError::NvBufferTooLarge)?;
        let mut command = command_header(TPM_ST_SESSIONS, TPM_CC_NV_WRITE);
        push_u32(&mut command, index);
        push_u32(&mut command, index);
        push_password_session(&mut command, auth)?;
        push_u16(&mut command, size);
        command.extend_from_slice(input);
        push_u16(&mut command, 0);
        finish_command_size(&mut command)?;
        let response = self.execute_success(&command)?;
        if !response_parameters(&response)?.is_empty() {
            return Err(TisTpmError::MalformedResponse);
        }
        Ok(())
    }

    fn increment(&mut self, index: u32, auth: &TpmNvIndexAuth) -> Result<(), Self::Error> {
        let mut command = command_header(TPM_ST_SESSIONS, TPM_CC_NV_INCREMENT);
        push_u32(&mut command, index);
        push_u32(&mut command, index);
        push_password_session(&mut command, auth)?;
        finish_command_size(&mut command)?;
        let response = self.execute_success(&command)?;
        if !response_parameters(&response)?.is_empty() {
            return Err(TisTpmError::MalformedResponse);
        }
        Ok(())
    }
}

fn command_header(tag: u16, command_code: u32) -> Vec<u8> {
    let mut command = Vec::with_capacity(256);
    push_u16(&mut command, tag);
    push_u32(&mut command, 0);
    push_u32(&mut command, command_code);
    command
}

fn push_password_session(command: &mut Vec<u8>, auth: &TpmNvIndexAuth) -> Result<(), TisTpmError> {
    let auth_len =
        u16::try_from(auth.as_bytes().len()).map_err(|_| TisTpmError::NvBufferTooLarge)?;
    let area_len = 4usize
        .checked_add(2)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(2))
        .and_then(|value| value.checked_add(usize::from(auth_len)))
        .ok_or(TisTpmError::CommandTooLarge)?;
    push_u32(
        command,
        u32::try_from(area_len).map_err(|_| TisTpmError::CommandTooLarge)?,
    );
    push_u32(command, TPM_RS_PW);
    push_u16(command, 0);
    command.push(0);
    push_u16(command, auth_len);
    command.extend_from_slice(auth.as_bytes());
    Ok(())
}

fn finish_command_size(command: &mut [u8]) -> Result<(), TisTpmError> {
    if command.len() > MAX_TPM_COMMAND {
        return Err(TisTpmError::CommandTooLarge);
    }
    let size = u32::try_from(command.len()).map_err(|_| TisTpmError::CommandTooLarge)?;
    command[2..6].copy_from_slice(&size.to_be_bytes());
    Ok(())
}

fn parse_nv_public(response: &[u8]) -> Result<TpmNvPublic, TisTpmError> {
    if response.len() < TPM_HEADER_LEN + 2
        || u16::from_be_bytes(response[..2].try_into().expect("TPM response tag"))
            != TPM_ST_NO_SESSIONS
    {
        return Err(TisTpmError::MalformedResponse);
    }
    let mut cursor = TPM_HEADER_LEN;
    let public_size = usize::from(take_u16_response(response, &mut cursor)?);
    let public_body_start = cursor;
    let public_end = cursor
        .checked_add(public_size)
        .ok_or(TisTpmError::MalformedResponse)?;
    if public_end > response.len() {
        return Err(TisTpmError::MalformedResponse);
    }
    let index = take_u32_response(response, &mut cursor)?;
    let name_algorithm = take_u16_response(response, &mut cursor)?;
    let attributes = take_u32_response(response, &mut cursor)?;
    let policy_len = usize::from(take_u16_response(response, &mut cursor)?);
    if policy_len != IMMUTABLE_DELETE_POLICY.len() {
        return Err(TisTpmError::MalformedResponse);
    }
    let policy_end = cursor
        .checked_add(policy_len)
        .filter(|end| *end <= public_end)
        .ok_or(TisTpmError::MalformedResponse)?;
    let authorization_policy = response[cursor..policy_end]
        .try_into()
        .map_err(|_| TisTpmError::MalformedResponse)?;
    cursor = policy_end;
    let data_size = take_u16_response(response, &mut cursor)?;
    if cursor != public_end {
        return Err(TisTpmError::MalformedResponse);
    }
    let name_size = usize::from(take_u16_response(response, &mut cursor)?);
    let name_end = cursor
        .checked_add(name_size)
        .filter(|end| *end == response.len())
        .ok_or(TisTpmError::MalformedResponse)?;
    if name_size != 2 + 32
        || u16::from_be_bytes(
            response[cursor..cursor + 2]
                .try_into()
                .expect("TPM Name algorithm"),
        ) != TPM_ALG_SHA256
    {
        return Err(TisTpmError::MalformedResponse);
    }
    let expected_name_digest = Sha256::digest(&response[public_body_start..public_end]);
    if expected_name_digest[..] != response[cursor + 2..name_end] {
        return Err(TisTpmError::MalformedResponse);
    }
    Ok(TpmNvPublic {
        index,
        name_algorithm,
        attributes,
        authorization_policy,
        data_size,
    })
}

fn response_parameters(response: &[u8]) -> Result<&[u8], TisTpmError> {
    if response.len() < TPM_HEADER_LEN + 4
        || u16::from_be_bytes(response[..2].try_into().expect("TPM response tag"))
            != TPM_ST_SESSIONS
    {
        return Err(TisTpmError::MalformedResponse);
    }
    let parameter_size = usize::try_from(u32::from_be_bytes(
        response[TPM_HEADER_LEN..TPM_HEADER_LEN + 4]
            .try_into()
            .expect("TPM response parameter size"),
    ))
    .map_err(|_| TisTpmError::MalformedResponse)?;
    let start = TPM_HEADER_LEN + 4;
    let end = start
        .checked_add(parameter_size)
        .filter(|end| *end <= response.len())
        .ok_or(TisTpmError::MalformedResponse)?;
    // Every provider command uses exactly one TPM_RS_PW session. Its response
    // must be an empty nonce, no attribute other than CONTINUESESSION, and an
    // empty HMAC, with no trailing bytes beyond that one TPMS_AUTH_RESPONSE.
    // Implementations differ on whether they echo CONTINUESESSION for the
    // password pseudo-session, so both zero and that single bit are accepted.
    let authorization = &response[end..];
    if authorization.len() != 5
        || authorization[..2] != [0, 0]
        || !matches!(authorization[2], 0 | TPMA_SESSION_CONTINUESESSION)
        || authorization[3..] != [0, 0]
    {
        return Err(TisTpmError::MalformedResponse);
    }
    Ok(&response[start..end])
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn take_u16_response(input: &[u8], cursor: &mut usize) -> Result<u16, TisTpmError> {
    let end = cursor
        .checked_add(2)
        .ok_or(TisTpmError::MalformedResponse)?;
    let bytes = input
        .get(*cursor..end)
        .ok_or(TisTpmError::MalformedResponse)?;
    *cursor = end;
    Ok(u16::from_be_bytes(
        bytes.try_into().expect("two-byte TPM response field"),
    ))
}

fn take_u32_response(input: &[u8], cursor: &mut usize) -> Result<u32, TisTpmError> {
    let end = cursor
        .checked_add(4)
        .ok_or(TisTpmError::MalformedResponse)?;
    let bytes = input
        .get(*cursor..end)
        .ok_or(TisTpmError::MalformedResponse)?;
    *cursor = end;
    Ok(u32::from_be_bytes(
        bytes.try_into().expect("four-byte TPM response field"),
    ))
}

/// Runs the dedicated QEMU `tpm-tis` provider profile.
///
/// The fixture reserves one recovery epoch and advances one trusted journal
/// tip per launch. Running the same image twice against one swtpm state
/// therefore proves that both selectors survive a guest/QEMU restart. The
/// marker explicitly excludes physical anti-rollback and device-reset
/// evidence: the host can roll back swtpm's state directory, and this profile
/// does not own a physical device.
pub(crate) fn launch() -> ! {
    let binding = RecoveryBinding::new(
        Digest::new([0x42; 32]),
        RegistryInstance::new(1).expect("fixture Registry identity is nonzero"),
        1,
    )
    .expect("fixture recovery binding is valid");
    let transport =
        QemuTisTpm2::acquire_qemu_fixture().expect("QEMU TPM2 TIS transport must be present");
    let auth = TpmNvIndexAuth::new(&[]).expect("empty fixture index auth fits");
    let mut anchor =
        TpmNvTrustedAnchor::open(transport, TpmNvLayout::qemu_fixture(), auth, binding)
            .expect("pre-provisioned TPM2 NV anchor must validate");

    let before = anchor.committed();
    let observed_device = anchor.issued.device();
    let lease = anchor
        .reserve_recovery_epoch(binding, observed_device)
        .expect("TPM2 NV recovery epoch reservation must commit");
    let next_revision = before
        .revision()
        .checked_add(1)
        .expect("fixture revision must not overflow");
    let mut digest_input = [0; 56];
    digest_input[..32].copy_from_slice(&before.head().bytes());
    digest_input[32..40].copy_from_slice(&next_revision.to_be_bytes());
    digest_input[40..48].copy_from_slice(&lease.next_freshness().boot().get().to_be_bytes());
    digest_input[48..56].copy_from_slice(&lease.next_freshness().journal().get().to_be_bytes());
    let next_head = Digest::new(Sha256::digest(digest_input).into());
    let replacement = TrustedAnchorSnapshot::from_trusted_backend(
        binding,
        lease.next_freshness(),
        next_revision,
        next_head,
    )
    .expect("fixture replacement trusted tip is valid");
    anchor
        .compare_and_advance(lease.committed(), replacement)
        .expect("TPM2 NV trusted tip advance must commit");

    println!(
        "CSER_TPM_NV_QEMU PASS transport=qemu-tis provider=tpm2-nv selectors=tip+lease single_writer_enforced=true writeall=true before_revision={} after_revision={} before_boot={} after_boot={} before_journal={} after_journal={} transition_committed=true physical_antirollback=false swtpm_state_rollbackable=true device_reset_evidence=false journal_payload=absent",
        before.revision(),
        replacement.revision(),
        before.committed_freshness().boot().get(),
        replacement.committed_freshness().boot().get(),
        before.committed_freshness().journal().get(),
        replacement.committed_freshness().journal().get(),
    );
    poweroff(ExitCode::Success)
}

const _: () = {
    assert!(TIP_SLOT_LEN <= u16::MAX as usize);
    assert!(LEASE_SLOT_LEN <= u16::MAX as usize);
    assert!(COUNTER_ATTRIBUTES & TPMA_NV_ORDERLY == 0);
    assert!(SLOT_ATTRIBUTES & TPMA_NV_ORDERLY == 0);
    assert!(COUNTER_ATTRIBUTES & TPMA_NV_TYPE_MASK == TPMA_NV_COUNTER);
    assert!(SLOT_ATTRIBUTES & TPMA_NV_TYPE_MASK == 0);
};

#[cfg(ktest)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use ostd::prelude::ktest;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockNvError {
        Missing,
        Size,
        Uninitialized,
        InjectedBeforeIncrement,
        InjectedAfterIncrement,
    }

    struct MockEntry {
        public: TpmNvPublic,
        bytes: Vec<u8>,
        initialized: bool,
    }

    struct MockNv {
        entries: BTreeMap<u32, MockEntry>,
        fail_before_increment: bool,
        fail_after_increment: bool,
    }

    impl MockNv {
        fn provision(
            layout: TpmNvLayout,
            sequence: u64,
            binding: RecoveryBinding,
            freshness: Freshness,
        ) -> Self {
            let mut entries = BTreeMap::new();
            insert_entry(
                &mut entries,
                layout.tip_counter,
                COUNTER_ATTRIBUTES,
                sequence.to_be_bytes().to_vec(),
                true,
            );
            for index in layout.tip_slots {
                insert_entry(
                    &mut entries,
                    index,
                    SLOT_ATTRIBUTES,
                    vec![0; TIP_SLOT_LEN],
                    false,
                );
            }
            insert_entry(
                &mut entries,
                layout.lease_counter,
                COUNTER_ATTRIBUTES,
                sequence.to_be_bytes().to_vec(),
                true,
            );
            for index in layout.lease_slots {
                insert_entry(
                    &mut entries,
                    index,
                    SLOT_ATTRIBUTES,
                    vec![0; LEASE_SLOT_LEN],
                    false,
                );
            }

            let genesis =
                TrustedAnchorSnapshot::from_trusted_backend(binding, freshness, 0, Digest::ZERO)
                    .unwrap();
            let tip_index = slot_for_sequence(layout.tip_slots, sequence);
            let tip = &mut entries.get_mut(&tip_index).unwrap();
            tip.bytes
                .copy_from_slice(&encode_tip_slot(sequence, genesis));
            tip.initialized = true;
            tip.public.attributes |= TPMA_NV_WRITTEN;

            let lease_index = slot_for_sequence(layout.lease_slots, sequence);
            let lease = &mut entries.get_mut(&lease_index).unwrap();
            lease
                .bytes
                .copy_from_slice(&encode_lease_slot(sequence, binding, freshness));
            lease.initialized = true;
            lease.public.attributes |= TPMA_NV_WRITTEN;

            Self {
                entries,
                fail_before_increment: false,
                fail_after_increment: false,
            }
        }
    }

    impl TpmNvTransport for MockNv {
        type Error = MockNvError;

        fn read_public(&mut self, index: u32) -> Result<TpmNvPublic, Self::Error> {
            self.entries
                .get(&index)
                .map(|entry| entry.public)
                .ok_or(MockNvError::Missing)
        }

        fn read_exact(
            &mut self,
            index: u32,
            _auth: &TpmNvIndexAuth,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            let entry = self.entries.get(&index).ok_or(MockNvError::Missing)?;
            if !entry.initialized {
                return Err(MockNvError::Uninitialized);
            }
            if entry.bytes.len() != output.len() {
                return Err(MockNvError::Size);
            }
            output.copy_from_slice(&entry.bytes);
            Ok(())
        }

        fn write_exact(
            &mut self,
            index: u32,
            _auth: &TpmNvIndexAuth,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            let entry = self.entries.get_mut(&index).ok_or(MockNvError::Missing)?;
            if entry.bytes.len() != input.len() {
                return Err(MockNvError::Size);
            }
            entry.bytes.copy_from_slice(input);
            entry.initialized = true;
            entry.public.attributes |= TPMA_NV_WRITTEN;
            Ok(())
        }

        fn increment(&mut self, index: u32, _auth: &TpmNvIndexAuth) -> Result<(), Self::Error> {
            if core::mem::take(&mut self.fail_before_increment) {
                return Err(MockNvError::InjectedBeforeIncrement);
            }
            let entry = self.entries.get_mut(&index).ok_or(MockNvError::Missing)?;
            if entry.bytes.len() != 8 || !entry.initialized {
                return Err(MockNvError::Size);
            }
            let value =
                u64::from_be_bytes(entry.bytes[..].try_into().map_err(|_| MockNvError::Size)?)
                    .checked_add(1)
                    .ok_or(MockNvError::Size)?;
            entry.bytes.copy_from_slice(&value.to_be_bytes());
            if core::mem::take(&mut self.fail_after_increment) {
                return Err(MockNvError::InjectedAfterIncrement);
            }
            Ok(())
        }
    }

    fn insert_entry(
        entries: &mut BTreeMap<u32, MockEntry>,
        index: u32,
        attributes: u32,
        bytes: Vec<u8>,
        initialized: bool,
    ) {
        entries.insert(
            index,
            MockEntry {
                public: TpmNvPublic {
                    index,
                    name_algorithm: TPM_ALG_SHA256,
                    attributes: attributes | if initialized { TPMA_NV_WRITTEN } else { 0 },
                    authorization_policy: IMMUTABLE_DELETE_POLICY,
                    data_size: u16::try_from(bytes.len()).unwrap(),
                },
                bytes,
                initialized,
            },
        );
    }

    fn digest(seed: u8) -> Digest {
        Digest::new([seed; 32])
    }

    fn binding() -> RecoveryBinding {
        RecoveryBinding::new(digest(7), RegistryInstance::new(9).unwrap(), 11).unwrap()
    }

    fn freshness(boot: u64, device: u64, journal: u64) -> Freshness {
        Freshness::new(
            BootGeneration::new(boot).unwrap(),
            RegistryInstance::new(9).unwrap(),
            11,
            DeviceGeneration::new(device).unwrap(),
            JournalGeneration::new(journal).unwrap(),
        )
        .unwrap()
    }

    fn auth() -> TpmNvIndexAuth {
        TpmNvIndexAuth::new(b"ktest-only-index-auth").unwrap()
    }

    #[ktest]
    fn reserve_and_tip_advance_survive_reopen() {
        let layout = TpmNvLayout::qemu_fixture();
        let transport = MockNv::provision(layout, 1, binding(), freshness(1, 1, 1));
        let mut anchor = TpmNvTrustedAnchor::open(transport, layout, auth(), binding()).unwrap();

        let lease = anchor
            .reserve_recovery_epoch(binding(), DeviceGeneration::new(2).unwrap())
            .unwrap();
        assert_eq!(lease.next_freshness(), freshness(2, 2, 2));
        let replacement = TrustedAnchorSnapshot::from_trusted_backend(
            binding(),
            lease.next_freshness(),
            1,
            digest(13),
        )
        .unwrap();
        anchor
            .compare_and_advance(lease.committed(), replacement)
            .unwrap();

        let reopened =
            TpmNvTrustedAnchor::open(anchor.into_transport(), layout, auth(), binding()).unwrap();
        assert_eq!(reopened.committed(), replacement);
        assert_eq!(reopened.tip_sequence, 2);
        assert_eq!(reopened.lease_sequence, 2);
    }

    #[ktest]
    fn crash_before_tip_counter_keeps_old_tip_selected() {
        let layout = TpmNvLayout::qemu_fixture();
        let transport = MockNv::provision(layout, 1, binding(), freshness(1, 1, 1));
        let mut anchor = TpmNvTrustedAnchor::open(transport, layout, auth(), binding()).unwrap();
        let old = anchor.committed();
        let replacement = TrustedAnchorSnapshot::from_trusted_backend(
            binding(),
            old.committed_freshness(),
            1,
            digest(17),
        )
        .unwrap();
        anchor.transport_mut().fail_before_increment = true;
        assert!(matches!(
            anchor.compare_and_advance(old, replacement),
            Err(TpmNvAnchorError::Transport(
                MockNvError::InjectedBeforeIncrement
            ))
        ));

        let reopened =
            TpmNvTrustedAnchor::open(anchor.into_transport(), layout, auth(), binding()).unwrap();
        assert_eq!(reopened.committed(), old);
        assert_eq!(reopened.tip_sequence, 1);
    }

    #[ktest]
    fn lost_increment_ack_reopens_at_new_tip() {
        let layout = TpmNvLayout::qemu_fixture();
        let transport = MockNv::provision(layout, 1, binding(), freshness(1, 1, 1));
        let mut anchor = TpmNvTrustedAnchor::open(transport, layout, auth(), binding()).unwrap();
        let old = anchor.committed();
        let replacement = TrustedAnchorSnapshot::from_trusted_backend(
            binding(),
            old.committed_freshness(),
            1,
            digest(19),
        )
        .unwrap();
        anchor.transport_mut().fail_after_increment = true;
        assert!(matches!(
            anchor.compare_and_advance(old, replacement),
            Err(TpmNvAnchorError::Transport(
                MockNvError::InjectedAfterIncrement
            ))
        ));

        let reopened =
            TpmNvTrustedAnchor::open(anchor.into_transport(), layout, auth(), binding()).unwrap();
        assert_eq!(reopened.committed(), replacement);
        assert_eq!(reopened.tip_sequence, 2);
    }

    #[ktest]
    fn corrupt_selected_slot_fails_closed() {
        let layout = TpmNvLayout::qemu_fixture();
        let mut transport = MockNv::provision(layout, 1, binding(), freshness(1, 1, 1));
        let selected = slot_for_sequence(layout.tip_slots, 1);
        transport.entries.get_mut(&selected).unwrap().bytes[31] ^= 0xff;
        assert!(matches!(
            TpmNvTrustedAnchor::open(transport, layout, auth(), binding()),
            Err(TpmNvAnchorError::CorruptSelectedSlot { index }) if index == selected
        ));
    }

    #[ktest]
    fn second_provider_is_rejected_before_an_interleaving_can_begin() {
        let layout = TpmNvLayout::qemu_fixture();
        let first_transport = MockNv::provision(layout, 1, binding(), freshness(1, 1, 1));
        let first = TpmNvTrustedAnchor::open(first_transport, layout, auth(), binding()).unwrap();
        let second_transport = MockNv::provision(layout, 1, binding(), freshness(1, 1, 1));
        assert!(matches!(
            TpmNvTrustedAnchor::open(second_transport, layout, auth(), binding()),
            Err(TpmNvAnchorError::ProviderAlreadyOpen)
        ));

        drop(first);
        let reopened_transport = MockNv::provision(layout, 1, binding(), freshness(1, 1, 1));
        let reopened =
            TpmNvTrustedAnchor::open(reopened_transport, layout, auth(), binding()).unwrap();
        assert_eq!(reopened.committed().revision(), 0);
    }
}
