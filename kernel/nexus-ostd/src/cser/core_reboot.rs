// SPDX-License-Identifier: MPL-2.0

//! Fail-closed boot boundary for persistent CSER recovery.
//!
//! The coordinator remains provider-generic, while the pinned
//! `cser-production` profile binds it to three independent concrete owners:
//!
//! - `AtaPioJournal` owns a dedicated primary ATA disk and performs banked
//!   journal append/repair with explicit ATA `FLUSH CACHE` commands;
//! - `TpmNvTrustedAnchor<QemuTisTpm2>` binds the catalog, Registry, journal tip,
//!   and recovery freshness to pre-provisioned TPM2 NV slots and counters; and
//! - `OstdVirtioBootQuarantine` acquires a linear `BootQuarantineGuard` before
//!   journal read or replay, performs the fixed PCI fence, VirtIO status reset,
//!   ISR drain, and global VT-d IOTLB command, and retains the device owner.
//!
//! Recovery reserves freshness only after the device quarantine exists.  It
//! replays exactly the trusted journal head, repairs at most one ignored
//! suffix, durably checkpoints the reserved boot epoch, and keeps the
//! quarantine guard alive.  No activation owner is returned until the core has
//! retired every recovered device claim and the hardware provider explicitly
//! releases the guard.
//!
//! The current receipt boundary remains the pinned QEMU raw-ATA and
//! `tpm-tis`/swtpm profile. It does not establish physical TPM anti-rollback,
//! physical power-loss durability, or crash-persistent PFN/IOVA custody. The
//! reset, ISR-drain, and global-IOTLB observations justify continued quarantine
//! only; they do not prove that retained resources were retired or may be
//! reused.

use alloc::{boxed::Box, vec::Vec};
use core::convert::Infallible;

#[cfg(ktest)]
use cser_core::scan_journal_to_head;
use cser_core::{
    CatalogSet, Command, CommandRequest, CoordinatedPersistence, CoordinatedPersistenceError,
    CoreError, CoreLimits, DeviceGeneration, Digest, DurableJournalBackend, Engine,
    JournalRecoverySource, JournalRepair, RecoveryAnchor, RecoveryBinding, RecoveryFromSourceError,
    RecoverySourceSnapshot, TransitionReceipt, TrustedAnchorBackend, TrustedAnchorSnapshot,
    TxError,
};
#[cfg(ktest)]
use sha2::{Digest as _, Sha256};

/// Fixed scratch used by the portable positioned recovery adapter.  Its size
/// is independent of the candidate's logical journal length.
const RECOVERY_SCRATCH_BYTES: usize = 4096;

/// One physically validated recovery image retained by a journal provider.
///
/// `generation` and `storage_digest` describe the provider's copy-on-write
/// metadata only.  They are deliberately never compared with a CSER record
/// revision or head: physical segment chains and logical journal chains are
/// different authorities.  The source retains the provider-specific payload
/// behind `slot`, while boot asks for bounded logical reads through
/// [`OstdBootJournal::read_recovery_at`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryCandidate {
    slot: u32,
    generation: u64,
    logical_len: usize,
    storage_digest: Digest,
}

impl RecoveryCandidate {
    /// Creates a provider-owned candidate descriptor.
    pub(crate) const fn new(
        slot: u32,
        generation: u64,
        logical_len: usize,
        storage_digest: Digest,
    ) -> Self {
        Self {
            slot,
            generation,
            logical_len,
            storage_digest,
        }
    }

    /// Provider-local candidate slot.
    pub(crate) const fn slot(self) -> u32 {
        self.slot
    }

    /// Physical copy-on-write generation, never a CSER authority coordinate.
    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }

    /// Number of logical CSER journal bytes exposed by this candidate.
    pub(crate) const fn logical_len(self) -> usize {
        self.logical_len
    }

    /// Digest of the provider's validated physical image metadata.
    pub(crate) const fn storage_digest(self) -> Digest {
        self.storage_digest
    }
}

/// Journal operations required before ordinary durable appends can resume.
pub(crate) trait OstdBootJournal: DurableJournalBackend {
    /// Error from boot-time reads or exact suffix repair.
    type RecoveryError;

    /// Enumerates every physically validated bank/manifest candidate.  The
    /// provider must retain all returned candidates until one is selected
    /// against the trusted CSER snapshot; it may not return only its newest
    /// physical generation.
    fn recovery_candidates(&mut self) -> Result<Vec<RecoveryCandidate>, Self::RecoveryError>;

    /// Installs the provider candidate chosen by the trusted logical anchor
    /// into the compatibility append cache.  Callers must invoke this only
    /// after the candidate has passed `Engine::recover`; before then the
    /// source remains read-at only. `None` denotes a validated blank medium
    /// at CSER genesis.
    fn select_recovery_candidate(
        &mut self,
        candidate: Option<RecoveryCandidate>,
    ) -> Result<(), Self::RecoveryError>;

    /// Reads a bounded logical range from one retained candidate.
    ///
    /// The source must not cache the complete logical image on behalf of this
    /// API or cache every candidate during enumeration.  A provider may keep
    /// a separately selected compatibility append cache, but it may read
    /// physical sectors into bounded scratch storage and translate
    /// framed/segmented layouts into the requested logical range.
    fn read_recovery_at(
        &mut self,
        candidate: RecoveryCandidate,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), Self::RecoveryError>;

    /// Revalidates the candidate snapshot immediately before a bounded read
    /// sequence.  Providers must recheck the exact header/manifest and its
    /// payload digest so a candidate enumerated before a media change cannot
    /// be stitched together from a newer image.
    fn revalidate_recovery_candidate(
        &mut self,
        candidate: RecoveryCandidate,
    ) -> Result<(), Self::RecoveryError>;

    /// Removes exactly the suffix named by anchored recovery and synchronizes
    /// the repaired durable image before returning.
    ///
    /// Returning an error is fail-closed.  The caller will not append or
    /// activate this journal instance.
    fn repair_and_sync(
        &mut self,
        repair: JournalRepair,
        candidate: Option<RecoveryCandidate>,
    ) -> Result<(), Self::RecoveryError>;
}

/// Linear owner of the boot-time hardware quarantine.
///
/// Dropping a guard must leave device DMA and interrupt authority disabled.
/// The only operation which may return a live device owner is
/// [`Self::try_activate`].
pub(crate) trait BootDeviceQuarantineGuard: Sized {
    /// Provider-specific activation failure.
    type Error;
    /// Live device owner returned only after successful release.
    type Activation;

    /// Monotonic device generation established while all managed devices are
    /// physically fenced.
    fn observed_generation(&self) -> DeviceGeneration;

    /// Attempts to release hardware quarantine.
    ///
    /// Failure returns the same guard so the caller cannot accidentally drop
    /// the only retained recovery owner.
    fn try_activate(self) -> Result<Self::Activation, (Self, Self::Error)>;
}

/// Provider which establishes physical quarantine before journal replay.
pub(crate) trait BootDeviceQuarantine: Sized {
    /// Provider-specific quarantine failure.
    type Error;
    /// Linear guard retaining the quarantined device owners.
    type Guard: BootDeviceQuarantineGuard;

    /// Fences every device which may be named by the persistent CSER Registry.
    ///
    /// A production implementation must disable new queue publication and
    /// interrupt delivery, retain DMA owners, and establish a reset-domain
    /// generation before returning.
    fn quarantine_all(self) -> Result<Self::Guard, Self::Error>;
}

/// Linear adapter for a device guard established before recovery coordination.
///
/// This lets boot code inspect trusted freshness, physically quarantine the
/// device, and validate a deployment binding while retaining that exact guard.
/// Passing the adapter to [`recover_quarantined_boot`] consumes it once and
/// cannot perform a second quarantine or manufacture another guard.
pub(crate) struct AlreadyQuarantined<G> {
    guard: G,
}

impl<G> AlreadyQuarantined<G> {
    /// Wraps the sole existing quarantine guard for one recovery attempt.
    pub(crate) const fn new(guard: G) -> Self {
        Self { guard }
    }
}

impl<G> BootDeviceQuarantine for AlreadyQuarantined<G>
where
    G: BootDeviceQuarantineGuard,
{
    type Error = Infallible;
    type Guard = G;

    fn quarantine_all(self) -> Result<Self::Guard, Self::Error> {
        Ok(self.guard)
    }
}

/// Trusted-provider contract violation detected after a freshness reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootProviderContractError {
    /// The lease describes a different Registry/catalog/binding tuple.
    RecoveryBindingMismatch,
    /// The lease does not bind the generation established by quarantine.
    DeviceGenerationMismatch,
}

/// Fail-closed result of matching physical candidates to one trusted CSER
/// tip.  A malformed logical stream is simply not a match; if no validated
/// candidate remains, recovery stops rather than guessing from generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootJournalSelectionError {
    /// No candidate contains the exact trusted logical revision/head chain.
    NoMatchingCandidate,
    /// The portable source adapter observed an impossible token/range
    /// violation.  This is a provider contract failure, not a candidate
    /// mismatch, and must stop boot rather than trying another copy.
    SourceContractViolation,
}

/// Failure while constructing one quarantined recovered boot.
#[derive(Debug)]
pub(crate) enum BootRecoveryError<JournalRecovery, JournalWrite, Anchor, Quarantine> {
    /// Hardware quarantine could not be established.
    Quarantine(Quarantine),
    /// Durable journal bytes could not be read.
    JournalRead(JournalRecovery),
    /// No unique logical candidate could be selected against the trusted tip.
    JournalSelection(BootJournalSelectionError),
    /// The exact ignored suffix could not be durably removed.
    JournalRepair(JournalRecovery),
    /// The trusted provider could not reserve a fresh recovery epoch.
    Anchor(Anchor),
    /// A provider returned coordinates outside its trusted contract.
    ProviderContract(BootProviderContractError),
    /// A reserved lease could not become the core's one-shot recovery anchor.
    RecoveryAnchor(cser_core::RecoveryAnchorError),
    /// Anchored journal replay rejected the bytes or freshness coordinates.
    Core(CoreError),
    /// Exact repair did not produce a clean anchored prefix.
    RepairDidNotConverge(JournalRepair),
    /// The recovery checkpoint failed or became ambiguous.
    Checkpoint(TxError<CoordinatedPersistenceError<JournalWrite, Anchor>>),
}

/// Why hardware activation remains blocked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootActivationBlock {
    /// A recovered journal tail still requires repair.
    JournalRepairRequired,
    /// A previous durability operation has an ambiguous result.
    PersistenceRecoveryRequired,
    /// At least one recovered device claim is still quarantined.
    DeviceClaimsRetained,
    /// The engine and trusted anchor do not name the same exact durable tip.
    TrustedTipMismatch,
}

/// Failed attempt to turn a quarantined recovery owner into an active owner.
#[derive(Debug)]
pub(crate) enum BootActivationFailure<Boot, ProviderError> {
    /// Core recovery state still forbids device activation.
    Blocked {
        /// Exact fail-closed reason.
        reason: BootActivationBlock,
        /// Unchanged boot owner retaining the quarantine guard.
        boot: Box<Boot>,
    },
    /// The hardware provider rejected release and returned its guard.
    Provider {
        /// Provider-specific failure.
        error: ProviderError,
        /// Reconstructed boot owner retaining the returned guard.
        boot: Box<Boot>,
    },
}

/// Recovered core whose physical device owners remain quarantined.
#[derive(Debug)]
pub(crate) struct QuarantinedRecoveredBoot<J, A, G> {
    engine: Engine,
    persistence: CoordinatedPersistence<J, A>,
    guard: G,
}

type DurableTxError<J, A> = TxError<
    CoordinatedPersistenceError<
        <J as DurableJournalBackend>::Error,
        <A as TrustedAnchorBackend>::Error,
    >,
>;

type ActivationResult<J, A, G> = Result<
    ActivatedRecoveredBoot<J, A, <G as BootDeviceQuarantineGuard>::Activation>,
    BootActivationFailure<
        QuarantinedRecoveredBoot<J, A, G>,
        <G as BootDeviceQuarantineGuard>::Error,
    >,
>;

type RecoveryResult<J, A, Q> = Result<
    QuarantinedRecoveredBoot<J, A, <Q as BootDeviceQuarantine>::Guard>,
    BootRecoveryError<
        <J as OstdBootJournal>::RecoveryError,
        <J as DurableJournalBackend>::Error,
        <A as TrustedAnchorBackend>::Error,
        <Q as BootDeviceQuarantine>::Error,
    >,
>;

impl<J, A, G> QuarantinedRecoveredBoot<J, A, G>
where
    J: OstdBootJournal,
    A: TrustedAnchorBackend,
    G: BootDeviceQuarantineGuard,
{
    /// Runs a read-only observation while no live device owner exists.
    pub(crate) fn observe<R>(&self, operation: impl FnOnce(&Engine) -> R) -> R {
        operation(&self.engine)
    }

    /// Runs one boot-reconciliation operation with simultaneous read-only
    /// access to the authoritative replay and mutable access to the retained
    /// hardware quarantine owner.
    ///
    /// The closure cannot issue a semantic transition: any verified evidence
    /// it constructs must still be committed through [`Self::recovery_transact`].
    /// Keeping the guard borrowed prevents a verifier from releasing or
    /// replacing the physical owner while it inspects an exact claim.
    pub(crate) fn inspect_with_guard<R>(
        &mut self,
        operation: impl FnOnce(&Engine, &mut G) -> R,
    ) -> R {
        operation(&self.engine, &mut self.guard)
    }

    /// Executes a manager-only recovery transition durably.
    ///
    /// This does not open external ingress or release the quarantine guard.
    pub(crate) fn recovery_transact<C>(
        &mut self,
        command: C,
    ) -> Result<TransitionReceipt, DurableTxError<J, A>>
    where
        C: Into<Command>,
    {
        self.engine.transact_durable(command, &mut self.persistence)
    }

    /// Returns the exact reason an activation permit cannot yet be issued.
    pub(crate) fn activation_block(&self) -> Option<BootActivationBlock> {
        if self.engine.journal_repair_required().is_some() {
            return Some(BootActivationBlock::JournalRepairRequired);
        }
        if self.engine.persistence_recovery_required() || self.persistence.recovery_required() {
            return Some(BootActivationBlock::PersistenceRecoveryRequired);
        }
        if self.engine.pressure().quarantined {
            return Some(BootActivationBlock::DeviceClaimsRetained);
        }
        let committed = self.persistence.committed();
        if self.engine.revision() != committed.revision()
            || self.engine.head() != committed.head()
            || self.engine.freshness() != committed.committed_freshness()
            || self.engine.projection_digest() != committed.projection()
        {
            return Some(BootActivationBlock::TrustedTipMismatch);
        }
        None
    }

    /// Consumes the quarantined owner and requests the sole activation token.
    pub(crate) fn try_activate(self) -> ActivationResult<J, A, G> {
        if let Some(reason) = self.activation_block() {
            return Err(BootActivationFailure::Blocked {
                reason,
                boot: Box::new(self),
            });
        }

        let Self {
            engine,
            persistence,
            guard,
        } = self;
        match guard.try_activate() {
            Ok(devices) => Ok(ActivatedRecoveredBoot {
                engine,
                persistence,
                devices,
            }),
            Err((guard, error)) => Err(BootActivationFailure::Provider {
                error,
                boot: Box::new(Self {
                    engine,
                    persistence,
                    guard,
                }),
            }),
        }
    }
}

/// Activation permit which couples the exact durable tip to live devices.
///
/// Constructing this type is impossible while journal repair, ambiguous
/// persistence, or recovered device claims still impose quarantine.
#[derive(Debug)]
pub(crate) struct ActivatedRecoveredBoot<J, A, D> {
    engine: Engine,
    persistence: CoordinatedPersistence<J, A>,
    devices: D,
}

impl<J, A, D> ActivatedRecoveredBoot<J, A, D>
where
    J: OstdBootJournal,
    A: TrustedAnchorBackend,
{
    /// Runs a read-only observation before the recovered parts are installed
    /// in the shared production owner.
    pub(crate) fn observe<R>(&self, operation: impl FnOnce(&Engine) -> R) -> R {
        operation(&self.engine)
    }

    /// Executes an ordinary durable transition after activation.
    pub(crate) fn transact<C>(
        &mut self,
        command: C,
    ) -> Result<TransitionReceipt, DurableTxError<J, A>>
    where
        C: Into<Command>,
    {
        self.engine.transact_durable(command, &mut self.persistence)
    }

    /// Transfers the exact core, persistence coordinator, and live device
    /// owner into the production runtime installation boundary.
    pub(crate) fn into_parts(self) -> (Engine, CoordinatedPersistence<J, A>, D) {
        (self.engine, self.persistence, self.devices)
    }
}

/// Errors which can be returned by the OSTD-to-core positioned adapter.
///
/// The provider error remains opaque and is mapped back to the boot journal
/// error.  The other variants are local contract failures: they cannot be
/// repaired by trying a different physical candidate.
#[derive(Debug)]
enum RecoverySourceError<E> {
    Provider(E),
    SnapshotMismatch,
    Range,
}

/// A stable, candidate-bound positioned source for the portable core.
///
/// The source owns no journal bytes. Its only state is the provider borrow
/// and the exact candidate token returned by `recovery_candidates`; every
/// read is therefore tied to the same provider snapshot and is bounded by
/// core's fixed scratch buffer.
struct CandidateRecoverySource<'a, J: OstdBootJournal> {
    journal: &'a mut J,
    candidate: RecoveryCandidate,
}

impl<J: OstdBootJournal> JournalRecoverySource for CandidateRecoverySource<'_, J> {
    type Error = RecoverySourceError<J::RecoveryError>;
    type Snapshot = RecoveryCandidate;

    fn begin_snapshot(&mut self) -> Result<RecoverySourceSnapshot<Self::Snapshot>, Self::Error> {
        self.journal
            .revalidate_recovery_candidate(self.candidate)
            .map_err(RecoverySourceError::Provider)?;
        let logical_len =
            u64::try_from(self.candidate.logical_len()).map_err(|_| RecoverySourceError::Range)?;
        Ok(RecoverySourceSnapshot::new(self.candidate, logical_len))
    }

    fn read_exact_at(
        &mut self,
        snapshot: Self::Snapshot,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        if snapshot != self.candidate {
            return Err(RecoverySourceError::SnapshotMismatch);
        }
        let offset = usize::try_from(offset).map_err(|_| RecoverySourceError::Range)?;
        self.journal
            .read_recovery_at(snapshot, offset, output)
            .map_err(RecoverySourceError::Provider)
    }

    fn validate_snapshot(&mut self, snapshot: Self::Snapshot) -> Result<(), Self::Error> {
        if snapshot != self.candidate {
            return Err(RecoverySourceError::SnapshotMismatch);
        }
        self.journal
            .revalidate_recovery_candidate(snapshot)
            .map_err(RecoverySourceError::Provider)
    }
}

/// Stable empty source used when the trusted genesis anchor has no physical
/// candidate. It avoids manufacturing even an empty journal image Vec in
/// the production recovery path.
struct EmptyRecoverySource;

impl JournalRecoverySource for EmptyRecoverySource {
    type Error = RecoverySourceError<Infallible>;
    type Snapshot = ();

    fn begin_snapshot(&mut self) -> Result<RecoverySourceSnapshot<Self::Snapshot>, Self::Error> {
        Ok(RecoverySourceSnapshot::new((), 0))
    }

    fn read_exact_at(
        &mut self,
        _snapshot: Self::Snapshot,
        _offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        if output.is_empty() {
            Ok(())
        } else {
            Err(RecoverySourceError::Range)
        }
    }

    fn validate_snapshot(&mut self, _snapshot: Self::Snapshot) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug)]
enum CandidateReadError<E> {
    Source(E),
    Selection(BootJournalSelectionError),
}

fn map_candidate_recovery_error<E>(
    error: RecoveryFromSourceError<RecoverySourceError<E>>,
) -> CandidateReadError<E> {
    match error {
        RecoveryFromSourceError::Source(RecoverySourceError::Provider(error)) => {
            CandidateReadError::Source(error)
        }
        RecoveryFromSourceError::Source(
            RecoverySourceError::SnapshotMismatch | RecoverySourceError::Range,
        )
        | RecoveryFromSourceError::EmptyScratch => {
            CandidateReadError::Selection(BootJournalSelectionError::SourceContractViolation)
        }
        RecoveryFromSourceError::Core(_) => {
            CandidateReadError::Selection(BootJournalSelectionError::NoMatchingCandidate)
        }
    }
}

/// Runs the authoritative source recovery once as candidate admission. A
/// core error means this physical candidate does not contain the trusted
/// logical head; provider/source errors remain fatal. The recovered engine
/// is dropped immediately, so no complete journal or checkpoint image is
/// retained between candidates.
fn candidate_matches<J>(
    journal: &mut J,
    candidate: RecoveryCandidate,
    catalogs: CatalogSet,
    limits: CoreLimits,
    committed: TrustedAnchorSnapshot,
    next_freshness: cser_core::Freshness,
    scratch: &mut [u8],
) -> Result<bool, CandidateReadError<J::RecoveryError>>
where
    J: OstdBootJournal,
{
    let anchor = RecoveryAnchor::from_trusted_provider(
        committed.binding(),
        committed.committed_freshness(),
        next_freshness,
        committed.revision(),
        committed.head(),
        committed.projection(),
    )
    .map_err(|_| {
        CandidateReadError::Selection(BootJournalSelectionError::SourceContractViolation)
    })?;
    let mut source = CandidateRecoverySource { journal, candidate };
    match Engine::recover_from_source(catalogs, limits, anchor, &mut source, scratch) {
        Ok(report) => Ok(report.acknowledged_revision() == committed.revision()
            && report.acknowledged_head() == committed.head()),
        Err(error) => match map_candidate_recovery_error(error) {
            CandidateReadError::Selection(BootJournalSelectionError::NoMatchingCandidate) => {
                Ok(false)
            }
            other => Err(other),
        },
    }
}

/// Selects a candidate only after the trusted backend has supplied the
/// committed CSER snapshot. Each trial uses the portable Core source path;
/// no candidate image is materialized. A successful trial proves the exact
/// authenticated prefix, so an equal-length second success has no distinct
/// logical authority to compare. A shorter success is preferred because any
/// bytes after its anchored prefix are repaired rather than trusted.
fn select_logical_candidate<J>(
    journal: &mut J,
    catalogs: &CatalogSet,
    limits: CoreLimits,
    committed: TrustedAnchorSnapshot,
    next_freshness: cser_core::Freshness,
    candidates: &[RecoveryCandidate],
    scratch: &mut [u8],
) -> Result<Option<RecoveryCandidate>, CandidateReadError<J::RecoveryError>>
where
    J: OstdBootJournal,
{
    if candidates.is_empty() {
        if committed.revision() == 0 {
            return Ok(None);
        }
        return Err(CandidateReadError::Selection(
            BootJournalSelectionError::NoMatchingCandidate,
        ));
    }

    let mut selected = None;
    for &candidate in candidates {
        if !candidate_matches(
            journal,
            candidate,
            catalogs.clone(),
            limits,
            committed,
            next_freshness,
            scratch,
        )? {
            continue;
        }
        let Some(current) = selected else {
            selected = Some(candidate);
            continue;
        };
        if candidate.logical_len() < current.logical_len() {
            selected = Some(candidate);
        }
    }
    selected
        .ok_or(CandidateReadError::Selection(
            BootJournalSelectionError::NoMatchingCandidate,
        ))
        .map(Some)
}

/// Test-only contiguous oracle retained for the candidate-selection unit
/// tests. Production recovery uses `CandidateRecoverySource` above and never
/// constructs this image.
#[cfg(ktest)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LogicalCandidateMatch {
    candidate: RecoveryCandidate,
    accepted_prefix_digest: Digest,
    full_image_digest: Digest,
}

#[cfg(ktest)]
fn logical_match(
    committed: TrustedAnchorSnapshot,
    candidate: RecoveryCandidate,
    image: &[u8],
) -> Option<LogicalCandidateMatch> {
    let accepted_len = if committed.revision() == 0 {
        0
    } else {
        let scan = match scan_journal_to_head(image, committed.head()) {
            Ok(Some(scan)) => scan,
            Ok(None) | Err(_) => return None,
        };
        let records = scan.records();
        let last = records.last()?;
        if last.revision() != committed.revision()
            || last.digest() != committed.head()
            || last.recovery_binding() != committed.binding()
            || last.boot() != committed.committed_freshness().boot()
            || last.registry() != committed.committed_freshness().registry()
            || last.journal() != committed.committed_freshness().journal()
            || last.device() != committed.committed_freshness().device()
            || records
                .iter()
                .any(|record| record.recovery_binding() != committed.binding())
        {
            return None;
        }
        scan.unanchored_suffix()
            .or(scan.torn_tail())
            .unwrap_or(image.len())
    };
    Some(LogicalCandidateMatch {
        candidate,
        accepted_prefix_digest: Digest::new(Sha256::digest(&image[..accepted_len]).into()),
        full_image_digest: Digest::new(Sha256::digest(image).into()),
    })
}

/// Recovers one boot while retaining every physical device owner.
///
/// One anchored suffix repair is permitted.  Because a [`RecoveryLease`] is
/// intentionally single-use, a repaired retry reserves a newer logical
/// recovery epoch even within the same physical boot.
pub(crate) fn recover_quarantined_boot<J, A, Q>(
    catalogs: CatalogSet,
    limits: CoreLimits,
    binding: RecoveryBinding,
    mut journal: J,
    mut anchor: A,
    quarantine: Q,
) -> RecoveryResult<J, A, Q>
where
    J: OstdBootJournal,
    A: TrustedAnchorBackend,
    Q: BootDeviceQuarantine,
{
    let guard = quarantine
        .quarantine_all()
        .map_err(BootRecoveryError::Quarantine)?;
    let observed_generation = guard.observed_generation();
    let mut repaired_once = false;

    loop {
        let lease = anchor
            .reserve_recovery_epoch(binding, observed_generation)
            .map_err(BootRecoveryError::Anchor)?;
        if lease.committed().binding() != binding {
            return Err(BootRecoveryError::ProviderContract(
                BootProviderContractError::RecoveryBindingMismatch,
            ));
        }
        if lease.next_freshness().device() != observed_generation {
            return Err(BootRecoveryError::ProviderContract(
                BootProviderContractError::DeviceGenerationMismatch,
            ));
        }

        // Do not inspect or choose a physical bank/manifest until the trusted
        // backend has supplied the committed CSER tip.  A newer valid copy is
        // only an unanchored suffix until this logical comparison accepts it.
        let candidates = journal
            .recovery_candidates()
            .map_err(BootRecoveryError::JournalRead)?;
        let next_freshness = lease.next_freshness();
        let mut scratch = [0u8; RECOVERY_SCRATCH_BYTES];
        let selected = select_logical_candidate(
            &mut journal,
            &catalogs,
            limits,
            lease.committed(),
            next_freshness,
            &candidates,
            &mut scratch,
        )
        .map_err(|error| match error {
            CandidateReadError::Source(error) => BootRecoveryError::JournalRead(error),
            CandidateReadError::Selection(error) => BootRecoveryError::JournalSelection(error),
        })?;
        let recovery_anchor = RecoveryAnchor::from_trusted_provider(
            lease.committed().binding(),
            lease.committed().committed_freshness(),
            next_freshness,
            lease.committed().revision(),
            lease.committed().head(),
            lease.committed().projection(),
        )
        .map_err(BootRecoveryError::RecoveryAnchor)?;
        let report = if let Some(candidate) = selected {
            let mut source = CandidateRecoverySource {
                journal: &mut journal,
                candidate,
            };
            Engine::recover_from_source(
                catalogs.clone(),
                limits,
                recovery_anchor,
                &mut source,
                &mut scratch,
            )
            .map_err(|error| match error {
                RecoveryFromSourceError::Source(RecoverySourceError::Provider(error)) => {
                    BootRecoveryError::JournalRead(error)
                }
                RecoveryFromSourceError::Source(
                    RecoverySourceError::SnapshotMismatch | RecoverySourceError::Range,
                )
                | RecoveryFromSourceError::EmptyScratch => {
                    BootRecoveryError::Core(CoreError::InvariantViolation)
                }
                RecoveryFromSourceError::Core(error) => BootRecoveryError::Core(error),
            })?
        } else {
            let mut source = EmptyRecoverySource;
            Engine::recover_from_source(
                catalogs.clone(),
                limits,
                recovery_anchor,
                &mut source,
                &mut scratch,
            )
            .map_err(|error| match error {
                RecoveryFromSourceError::Source(RecoverySourceError::Provider(never)) => {
                    match never {}
                }
                RecoveryFromSourceError::Source(
                    RecoverySourceError::SnapshotMismatch | RecoverySourceError::Range,
                )
                | RecoveryFromSourceError::EmptyScratch => {
                    BootRecoveryError::Core(CoreError::InvariantViolation)
                }
                RecoveryFromSourceError::Core(error) => BootRecoveryError::Core(error),
            })?
        };
        let mut persistence = CoordinatedPersistence::from_recovery_lease(journal, anchor, &lease);

        if let Some(repair) = report.journal_repair() {
            if repaired_once {
                return Err(BootRecoveryError::RepairDidNotConverge(repair));
            }
            let (mut recovered_journal, recovered_anchor) = persistence.into_backends();
            recovered_journal
                .repair_and_sync(repair, selected)
                .map_err(BootRecoveryError::JournalRepair)?;
            journal = recovered_journal;
            anchor = recovered_anchor;
            repaired_once = true;
            continue;
        }

        // Only a successful, already-validated logical recovery may install
        // the provider's compatibility append cache. Before this point all
        // candidate reads were source read-at operations against the trusted
        // lease; physical generation has not become authority.
        persistence
            .inspect_journal(|journal| journal.select_recovery_candidate(selected))
            .map_err(BootRecoveryError::JournalRead)?;

        let mut engine = report.into_engine();
        engine
            .transact_durable(
                CommandRequest::CheckpointRecovery {
                    boot: next_freshness.boot(),
                    journal: next_freshness.journal(),
                    device: next_freshness.device(),
                },
                &mut persistence,
            )
            .map_err(BootRecoveryError::Checkpoint)?;
        return Ok(QuarantinedRecoveredBoot {
            engine,
            persistence,
            guard,
        });
    }
}

#[cfg(ktest)]
mod tests {
    use super::*;
    use alloc::vec;
    use cser_core::{
        BootGeneration, ChargeAccountId, ClaimId, ClaimScope, ComponentProviderBinding,
        DEVICE_CLAIM_QUEUE_SLOT, DMA_ARENA_REUSE_COMPOSITE, DeviceScopeId, Digest, EffectId,
        ExecutorCoordinate, ExecutorGeneration, ExecutorId, Freshness, JournalGeneration,
        OperationId, ProviderCoordinate, ProviderGeneration, ProviderId, RecoveryProfile,
        RegistryInstance, ResourceGeneration, ResourceId, TrustedAnchorSnapshot, VerifierBinding,
        VerifierGeneration, WorldId, standard_catalog,
    };
    use ostd::prelude::ktest;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Binding,
        Stale,
        Repair,
    }

    #[derive(Debug)]
    struct MemoryJournal {
        bytes: Vec<u8>,
        repairs: u8,
    }

    impl DurableJournalBackend for MemoryJournal {
        type Error = MockError;

        fn append_and_sync(
            &mut self,
            record: &cser_core::JournalRecord,
        ) -> Result<(), Self::Error> {
            self.bytes.extend_from_slice(record.bytes());
            Ok(())
        }
    }

    impl OstdBootJournal for MemoryJournal {
        type RecoveryError = MockError;

        fn recovery_candidates(&mut self) -> Result<Vec<RecoveryCandidate>, Self::RecoveryError> {
            if self.bytes.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(vec![RecoveryCandidate::new(
                    0,
                    1,
                    self.bytes.len(),
                    Digest::ZERO,
                )])
            }
        }

        fn select_recovery_candidate(
            &mut self,
            _candidate: Option<RecoveryCandidate>,
        ) -> Result<(), Self::RecoveryError> {
            Ok(())
        }

        fn read_recovery_at(
            &mut self,
            _candidate: RecoveryCandidate,
            offset: usize,
            output: &mut [u8],
        ) -> Result<(), Self::RecoveryError> {
            let end = offset.checked_add(output.len()).ok_or(MockError::Repair)?;
            if end > self.bytes.len() {
                return Err(MockError::Repair);
            }
            output.copy_from_slice(&self.bytes[offset..end]);
            Ok(())
        }

        fn revalidate_recovery_candidate(
            &mut self,
            candidate: RecoveryCandidate,
        ) -> Result<(), Self::RecoveryError> {
            if candidate.logical_len() != self.bytes.len() {
                return Err(MockError::Repair);
            }
            Ok(())
        }

        fn repair_and_sync(
            &mut self,
            repair: JournalRepair,
            _candidate: Option<RecoveryCandidate>,
        ) -> Result<(), Self::RecoveryError> {
            let offset = match repair {
                JournalRepair::TornTail { offset } | JournalRepair::UnanchoredSuffix { offset } => {
                    offset
                }
            };
            if offset > self.bytes.len() {
                return Err(MockError::Repair);
            }
            self.bytes.truncate(offset);
            self.repairs = self.repairs.checked_add(1).ok_or(MockError::Repair)?;
            Ok(())
        }
    }

    #[derive(Debug)]
    struct MemoryAnchor {
        committed: TrustedAnchorSnapshot,
        issued: Freshness,
        reservations: u8,
    }

    impl TrustedAnchorBackend for MemoryAnchor {
        type Error = MockError;

        fn reserve_recovery_epoch(
            &mut self,
            binding: RecoveryBinding,
            observed_device: DeviceGeneration,
        ) -> Result<cser_core::RecoveryLease, Self::Error> {
            if binding != self.committed.binding() {
                return Err(MockError::Binding);
            }
            if observed_device.get() < self.issued.device().get() {
                return Err(MockError::Stale);
            }
            let boot = BootGeneration::new(
                self.issued
                    .boot()
                    .get()
                    .checked_add(1)
                    .ok_or(MockError::Stale)?,
            )
            .map_err(|_| MockError::Stale)?;
            let journal = JournalGeneration::new(
                self.issued
                    .journal()
                    .get()
                    .checked_add(1)
                    .ok_or(MockError::Stale)?,
            )
            .map_err(|_| MockError::Stale)?;
            let next = Freshness::new(boot, binding.registry(), observed_device, journal);
            self.issued = next;
            self.reservations = self.reservations.checked_add(1).ok_or(MockError::Stale)?;
            cser_core::RecoveryLease::from_trusted_backend(self.committed, next)
                .map_err(|_| MockError::Stale)
        }

        fn compare_and_advance(
            &mut self,
            expected: TrustedAnchorSnapshot,
            replacement: TrustedAnchorSnapshot,
        ) -> Result<(), Self::Error> {
            if expected != self.committed
                || expected.revision().checked_add(1) != Some(replacement.revision())
                || replacement.committed_freshness() != self.issued
            {
                return Err(MockError::Stale);
            }
            self.committed = replacement;
            Ok(())
        }
    }

    #[derive(Debug)]
    struct MockQuarantine {
        observed: DeviceGeneration,
        reject_activation: bool,
    }

    #[derive(Debug)]
    struct MockGuard {
        observed: DeviceGeneration,
        reject_activation: bool,
    }

    #[derive(Debug)]
    struct MockLiveDevices;

    impl BootDeviceQuarantine for MockQuarantine {
        type Error = MockError;
        type Guard = MockGuard;

        fn quarantine_all(self) -> Result<Self::Guard, Self::Error> {
            Ok(MockGuard {
                observed: self.observed,
                reject_activation: self.reject_activation,
            })
        }
    }

    impl BootDeviceQuarantineGuard for MockGuard {
        type Error = MockError;
        type Activation = MockLiveDevices;

        fn observed_generation(&self) -> DeviceGeneration {
            self.observed
        }

        fn try_activate(self) -> Result<Self::Activation, (Self, Self::Error)> {
            if self.reject_activation {
                Err((self, MockError::Stale))
            } else {
                Ok(MockLiveDevices)
            }
        }
    }

    fn initial_freshness(device: u64) -> Freshness {
        Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(17).unwrap(),
            DeviceGeneration::new(device).unwrap(),
            JournalGeneration::new(1).unwrap(),
        )
    }

    fn catalog_set() -> CatalogSet {
        let catalog = standard_catalog();
        CatalogSet::new(core::slice::from_ref(&catalog)).unwrap()
    }

    fn binding() -> RecoveryBinding {
        RecoveryBinding::new(
            RecoveryProfile::current(),
            WorldId::new(1).unwrap(),
            catalog_set().digest(),
            RegistryInstance::new(17).unwrap(),
        )
        .unwrap()
    }

    fn genesis_anchor() -> MemoryAnchor {
        let freshness = initial_freshness(1);
        let projection = Engine::new(
            WorldId::new(1).unwrap(),
            catalog_set(),
            CoreLimits::bounded_default(),
            freshness,
        )
        .projection_digest();
        MemoryAnchor {
            committed: TrustedAnchorSnapshot::from_trusted_backend(
                binding(),
                freshness,
                0,
                Digest::ZERO,
                projection,
            )
            .unwrap(),
            issued: freshness,
            reservations: 0,
        }
    }

    fn quarantined_device_fixture() -> (MemoryJournal, MemoryAnchor) {
        let catalog = standard_catalog();
        let catalogs = CatalogSet::new(core::slice::from_ref(&catalog)).unwrap();
        let world = WorldId::new(1).unwrap();
        let provider = ProviderCoordinate::new(
            world,
            ProviderId::new(1).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        let verifier_generation = VerifierGeneration::new(1).unwrap();
        let verifier_bindings = catalog
            .verifier_class_bindings()
            .into_iter()
            .enumerate()
            .map(|(index, class)| {
                VerifierBinding::new(
                    class.verifier(),
                    verifier_generation,
                    class.receipt_schema(),
                    Digest::new([0x40u8.wrapping_add(index as u8); 32]),
                )
                .unwrap()
            })
            .collect();
        let mut engine = Engine::new(
            world,
            catalogs,
            CoreLimits::bounded_default(),
            initial_freshness(1),
        );
        let mut bytes = Vec::new();
        engine
            .transact(
                CommandRequest::RegisterProviderGeneration {
                    coordinate: provider,
                    catalog_digest: catalog.digest(),
                    verifier_bindings,
                },
                |record| {
                    bytes.extend_from_slice(record.bytes());
                    Ok::<(), MockError>(())
                },
            )
            .unwrap();
        let operation = OperationId::new(9).unwrap();
        let effect = EffectId::new(operation, 1).unwrap();
        let actor = ExecutorCoordinate::new(
            ExecutorId::new(5).unwrap(),
            ExecutorGeneration::new(1).unwrap(),
        );
        for command in [
            CommandRequest::AdmitScopedCompositeEffect {
                effect,
                origin: actor,
                kind: DMA_ARENA_REUSE_COMPOSITE,
                charge_account: ChargeAccountId::new(7).unwrap(),
                bindings: vec![ComponentProviderBinding::new(
                    cser_core::AGENT_COMPONENT_DMA,
                    provider,
                )],
            },
            CommandRequest::AddComponentClaim {
                effect,
                component: cser_core::AGENT_COMPONENT_DMA,
                actor,
                claim: ClaimId::new(1).unwrap(),
                kind: DEVICE_CLAIM_QUEUE_SLOT,
                scope: ClaimScope::Device(DeviceScopeId::new(11).unwrap()),
                resource: ResourceId::new(31).unwrap(),
                resource_generation: ResourceGeneration::new(1).unwrap(),
                units: 1,
            },
        ] {
            engine
                .transact(command, |record| {
                    bytes.extend_from_slice(record.bytes());
                    Ok::<(), MockError>(())
                })
                .unwrap();
        }
        let committed = TrustedAnchorSnapshot::from_trusted_backend(
            binding(),
            engine.freshness(),
            engine.revision(),
            engine.head(),
            engine.projection_digest(),
        )
        .unwrap();
        (
            MemoryJournal { bytes, repairs: 0 },
            MemoryAnchor {
                committed,
                issued: engine.freshness(),
                reservations: 0,
            },
        )
    }

    #[ktest]
    fn already_quarantined_consumes_the_existing_guard_once() {
        let observed = DeviceGeneration::new(2).unwrap();
        let guard = AlreadyQuarantined::new(MockGuard {
            observed,
            reject_activation: false,
        })
        .quarantine_all()
        .unwrap();

        assert_eq!(guard.observed_generation(), observed);
        assert!(guard.try_activate().is_ok());
    }

    #[ktest]
    fn clean_boot_checkpoints_before_returning_activation_owner() {
        let boot = recover_quarantined_boot(
            catalog_set(),
            CoreLimits::bounded_default(),
            binding(),
            MemoryJournal {
                bytes: Vec::new(),
                repairs: 0,
            },
            genesis_anchor(),
            MockQuarantine {
                observed: DeviceGeneration::new(2).unwrap(),
                reject_activation: false,
            },
        )
        .unwrap();

        assert_eq!(boot.activation_block(), None);
        let active = boot.try_activate().unwrap();
        let (engine, persistence, _devices) = active.into_parts();
        assert_eq!(engine.revision(), 1);
        assert_eq!(engine.freshness().boot().get(), 2);
        assert_eq!(engine.freshness().journal().get(), 2);
        assert_eq!(engine.freshness().device().get(), 2);
        assert_eq!(engine.head(), persistence.committed().head());
    }

    #[ktest]
    fn retained_device_claim_prevents_activation_after_reboot() {
        let (journal, anchor) = quarantined_device_fixture();
        let boot = recover_quarantined_boot(
            catalog_set(),
            CoreLimits::bounded_default(),
            binding(),
            journal,
            anchor,
            MockQuarantine {
                observed: DeviceGeneration::new(2).unwrap(),
                reject_activation: false,
            },
        )
        .unwrap();

        assert_eq!(
            boot.activation_block(),
            Some(BootActivationBlock::DeviceClaimsRetained)
        );
        assert!(matches!(
            boot.try_activate(),
            Err(BootActivationFailure::Blocked {
                reason: BootActivationBlock::DeviceClaimsRetained,
                ..
            })
        ));
    }

    #[ktest]
    fn ignored_suffix_is_repaired_before_a_newer_recovery_epoch() {
        let boot = recover_quarantined_boot(
            catalog_set(),
            CoreLimits::bounded_default(),
            binding(),
            MemoryJournal {
                bytes: vec![0xaa, 0xbb],
                repairs: 0,
            },
            genesis_anchor(),
            MockQuarantine {
                observed: DeviceGeneration::new(2).unwrap(),
                reject_activation: false,
            },
        )
        .unwrap();

        let active = boot.try_activate().unwrap();
        let (engine, persistence, _devices) = active.into_parts();
        assert_eq!(engine.freshness().boot().get(), 3);
        assert_eq!(engine.freshness().journal().get(), 3);
        let (journal, anchor) = persistence.into_backends();
        assert_eq!(journal.repairs, 1);
        assert_eq!(anchor.reservations, 2);
    }

    #[ktest]
    fn provider_release_failure_returns_the_quarantine_guard() {
        let boot = recover_quarantined_boot(
            catalog_set(),
            CoreLimits::bounded_default(),
            binding(),
            MemoryJournal {
                bytes: Vec::new(),
                repairs: 0,
            },
            genesis_anchor(),
            MockQuarantine {
                observed: DeviceGeneration::new(2).unwrap(),
                reject_activation: true,
            },
        )
        .unwrap();

        let failure = boot.try_activate().unwrap_err();
        let BootActivationFailure::Provider { error, boot } = failure else {
            panic!("provider rejection must preserve its guard");
        };
        assert_eq!(error, MockError::Stale);
        assert_eq!(boot.activation_block(), None);
    }

    #[ktest]
    fn logical_candidate_matching_ignores_physical_generation_and_suffix() {
        let (journal, anchor) = quarantined_device_fixture();
        let committed = anchor.committed;
        let exact = RecoveryCandidate::new(0, 7, journal.bytes.len(), Digest::new([0x11; 32]));
        let exact_match = logical_match(committed, exact, &journal.bytes)
            .expect("trusted logical head matches the exact candidate");

        let mut suffix = journal.bytes.clone();
        suffix.extend_from_slice(b"unanchored-newer-copy");
        let newer = RecoveryCandidate::new(1, 900, suffix.len(), Digest::new([0x22; 32]));
        let newer_match = logical_match(committed, newer, &suffix)
            .expect("trusted prefix matches despite an unanchored suffix");
        assert_eq!(
            exact_match.accepted_prefix_digest,
            newer_match.accepted_prefix_digest
        );
        assert!(newer.logical_len() > exact.logical_len());
        assert_ne!(exact.generation(), newer.generation());
    }

    #[ktest]
    fn logical_candidate_matching_rejects_a_different_trusted_head() {
        let (journal, anchor) = quarantined_device_fixture();
        let committed = anchor.committed;
        let wrong = TrustedAnchorSnapshot::from_trusted_backend(
            committed.binding(),
            committed.committed_freshness(),
            committed.revision(),
            Digest::new([0x77; 32]),
            committed.projection(),
        )
        .expect("wrong digest still has structurally valid anchor coordinates");
        let candidate = RecoveryCandidate::new(0, 1, journal.bytes.len(), Digest::new([0x33; 32]));
        assert!(logical_match(wrong, candidate, &journal.bytes).is_none());
    }

    #[ktest]
    fn recovery_fails_closed_when_no_candidate_matches_the_committed_head() {
        let (journal, mut anchor) = quarantined_device_fixture();
        let committed = anchor.committed;
        anchor.committed = TrustedAnchorSnapshot::from_trusted_backend(
            committed.binding(),
            committed.committed_freshness(),
            committed.revision(),
            Digest::new([0x78; 32]),
            committed.projection(),
        )
        .expect("wrong digest still has structurally valid anchor coordinates");
        let result = recover_quarantined_boot(
            catalog_set(),
            CoreLimits::bounded_default(),
            binding(),
            journal,
            anchor,
            MockQuarantine {
                observed: DeviceGeneration::new(2).unwrap(),
                reject_activation: false,
            },
        );

        assert!(matches!(
            result,
            Err(BootRecoveryError::JournalSelection(
                BootJournalSelectionError::NoMatchingCandidate
            ))
        ));
    }
}
