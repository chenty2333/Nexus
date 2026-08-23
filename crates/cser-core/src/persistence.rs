// SPDX-License-Identifier: MPL-2.0

//! Portable contracts for durable journal and trusted-freshness providers.
//!
//! A production embedding needs two failure domains:
//!
//! 1. journal storage which appends the exact record and completes its
//!    durability barrier; and
//! 2. a small, atomic trusted anchor which cannot be rolled back together with
//!    that journal.
//!
//! [`CoordinatedPersistence`] always completes (1) before requesting (2). Any
//! error from either boundary is ambiguous and permanently latches that
//! instance until it is dropped and recovered from the trusted anchor.

use crate::{
    CheckpointAnchor, CheckpointRecordPlan, Digest, Freshness, JournalRecord, PreparedCheckpoint,
    RecoveryAnchor, RecoveryAnchorError, RegistryInstance, WorldId,
};

/// Immutable schema coordinates which govern one recovery domain.
///
/// The tuple is deliberately kept separate from the mutable projection. A
/// recovery binding identifies the code and catalog which interpret a journal;
/// provider generations, verifier epochs, and artifact leases are state and
/// are authenticated by the projection instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryProfile {
    core_api: u16,
    journal_schema: u16,
    projection_schema: u16,
    checkpoint_schema: u16,
}

#[path = "rollover_persistence.rs"]
mod rollover_persistence;
pub use rollover_persistence::{WorldRolloverAnchorBackend, WorldRolloverDurability};

impl RecoveryProfile {
    /// Creates an exact immutable schema tuple.
    pub const fn new(
        core_api: u16,
        journal_schema: u16,
        projection_schema: u16,
        checkpoint_schema: u16,
    ) -> Result<Self, PersistenceProtocolError> {
        if core_api == 0 || journal_schema == 0 || projection_schema == 0 || checkpoint_schema == 0
        {
            return Err(PersistenceProtocolError::InvalidAnchor);
        }
        Ok(Self {
            core_api,
            journal_schema,
            projection_schema,
            checkpoint_schema,
        })
    }

    /// Returns the current CSER Core schema tuple.
    pub const fn current() -> Self {
        Self {
            core_api: crate::CSER_CORE_API_PROFILE_VERSION,
            journal_schema: crate::JOURNAL_SCHEMA_VERSION,
            projection_schema: crate::PROJECTION_VERSION,
            checkpoint_schema: crate::JOURNAL_CHECKPOINT_VERSION,
        }
    }

    /// Returns the semantic core API coordinate.
    pub const fn core_api(self) -> u16 {
        self.core_api
    }
    /// Returns the journal wire schema coordinate.
    pub const fn journal_schema(self) -> u16 {
        self.journal_schema
    }
    /// Returns the authenticated projection schema coordinate.
    pub const fn projection_schema(self) -> u16 {
        self.projection_schema
    }
    /// Returns the checkpoint envelope schema coordinate.
    pub const fn checkpoint_schema(self) -> u16 {
        self.checkpoint_schema
    }
}

/// Stable schema and recovery coordinates expected at boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryBinding {
    profile: RecoveryProfile,
    world: WorldId,
    catalog_digest: Digest,
    registry: RegistryInstance,
}

impl RecoveryBinding {
    /// Creates an exact recovery binding for an immutable catalog set.
    pub const fn new(
        profile: RecoveryProfile,
        world: WorldId,
        catalog_digest: Digest,
        registry: RegistryInstance,
    ) -> Result<Self, PersistenceProtocolError> {
        if catalog_digest.is_zero() {
            return Err(PersistenceProtocolError::InvalidAnchor);
        }
        Ok(Self {
            profile,
            world,
            catalog_digest,
            registry,
        })
    }

    /// Returns the immutable schema tuple.
    pub const fn profile(self) -> RecoveryProfile {
        self.profile
    }

    /// Returns the semantic world allocated by the embedding.
    pub const fn world(self) -> WorldId {
        self.world
    }

    /// Returns the aggregate digest of the immutable catalog set expected for
    /// recovery. Per-effect/provider schema digests remain in their records.
    pub const fn catalog_digest(self) -> Digest {
        self.catalog_digest
    }

    /// Returns the expected durable Registry identity.
    pub const fn registry(self) -> RegistryInstance {
        self.registry
    }
}

/// Exact journal tip atomically protected by a trusted anchor backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedAnchorSnapshot {
    binding: RecoveryBinding,
    committed_freshness: Freshness,
    revision: u64,
    head: Digest,
    projection: Digest,
}

impl TrustedAnchorSnapshot {
    /// Constructs a snapshot read from a trusted platform backend.
    ///
    /// This constructor validates structure only. Calling it asserts that the
    /// values came from an atomic, non-rollback platform store.
    pub const fn from_trusted_backend(
        binding: RecoveryBinding,
        committed_freshness: Freshness,
        revision: u64,
        head: Digest,
        projection: Digest,
    ) -> Result<Self, PersistenceProtocolError> {
        if committed_freshness.registry().get() != binding.registry().get() {
            return Err(PersistenceProtocolError::BindingMismatch);
        }
        if projection.is_zero() || (revision == 0) != head.is_zero() {
            return Err(PersistenceProtocolError::InvalidAnchor);
        }
        Ok(Self {
            binding,
            committed_freshness,
            revision,
            head,
            projection,
        })
    }

    /// Returns the protected schema and binding.
    pub const fn binding(self) -> RecoveryBinding {
        self.binding
    }

    /// Returns freshness of the acknowledged journal tip.
    pub const fn committed_freshness(self) -> Freshness {
        self.committed_freshness
    }

    /// Returns the acknowledged journal revision.
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Returns the acknowledged journal head.
    pub const fn head(self) -> Digest {
        self.head
    }

    /// Returns the exact final state projection at the acknowledged tip.
    pub const fn projection(self) -> Digest {
        self.projection
    }
}

/// Single boot's atomically reserved recovery epoch.
///
/// A backend must durably reserve `next_freshness` before returning this
/// value. Repeating boot recovery must reserve a strictly newer boot and
/// journal generation, even if the previous boot died before checkpointing.
#[derive(Debug, Eq, PartialEq)]
pub struct RecoveryLease {
    committed: TrustedAnchorSnapshot,
    next_freshness: Freshness,
}

impl RecoveryLease {
    /// Constructs a lease after a trusted backend atomically reserved it.
    pub fn from_trusted_backend(
        committed: TrustedAnchorSnapshot,
        next_freshness: Freshness,
    ) -> Result<Self, PersistenceProtocolError> {
        RecoveryAnchor::from_trusted_provider(
            committed.binding(),
            committed.committed_freshness(),
            next_freshness,
            committed.revision(),
            committed.head(),
            committed.projection(),
        )
        .map_err(PersistenceProtocolError::RecoveryAnchor)?;
        Ok(Self {
            committed,
            next_freshness,
        })
    }

    /// Returns the currently committed trusted tip.
    pub const fn committed(&self) -> TrustedAnchorSnapshot {
        self.committed
    }

    /// Returns the new epoch reserved for this recovery.
    pub const fn next_freshness(&self) -> Freshness {
        self.next_freshness
    }

    /// Consumes the lease into the core's single-use recovery anchor.
    pub fn into_recovery_anchor(self) -> Result<RecoveryAnchor, RecoveryAnchorError> {
        RecoveryAnchor::from_trusted_provider(
            self.committed.binding(),
            self.committed.committed_freshness(),
            self.next_freshness,
            self.committed.revision(),
            self.committed.head(),
            self.committed.projection(),
        )
    }
}

/// Portable protocol violation detected before a backend operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceProtocolError {
    /// A zero digest or inconsistent genesis coordinates were supplied.
    InvalidAnchor,
    /// Catalog, Registry, schema, or world coordinates do not match.
    BindingMismatch,
    /// A record does not extend the exact trusted journal tip.
    StaleJournalHead,
    /// Resulting freshness is stale or was not reserved for this recovery.
    StaleFreshness,
    /// No whole-state checkpoint is currently eligible to replace the replay image.
    NoCommittedCheckpoint,
    /// The committed checkpoint exceeds this backend's replacement capacity.
    CheckpointTooLarge,
    /// This coordinator observed an ambiguous failure and must be reopened.
    RecoveryRequired,
    /// The core rejected construction of the corresponding recovery anchor.
    RecoveryAnchor(RecoveryAnchorError),
}

/// Journal backend which makes one complete record durable before success.
pub trait DurableJournalBackend {
    /// Backend-specific failure.
    type Error;

    /// Appends `record.bytes()` exactly and completes the required durability barrier.
    ///
    /// A returned error is always ambiguous: some or all bytes may already be
    /// durable. The caller will not issue another append until anchored
    /// recovery and suffix repair complete.
    fn append_and_sync(&mut self, record: &JournalRecord) -> Result<(), Self::Error>;
}

/// Durable journal backend that can atomically replace its replay image with
/// one already-committed whole-state checkpoint record.
///
/// This capability is intentionally separate from [`DurableJournalBackend`].
/// A legacy append-only implementation must not claim that a normal record is
/// sufficient authority to discard its prefix.
pub trait CompactingJournalBackend: DurableJournalBackend {
    /// Returns the largest exact checkpoint image this backend can replace.
    fn checkpoint_capacity_bytes(&self) -> usize;

    /// Replaces the durable replay image with `checkpoint.bytes()` exactly.
    ///
    /// The caller has already made this record authoritative through the
    /// trusted anchor. An error is ambiguous: the replacement may have become
    /// durable before its acknowledgement was lost.
    fn replace_with_checkpoint(&mut self, checkpoint: &JournalRecord) -> Result<(), Self::Error>;
}

/// Atomic trusted-anchor backend supplied by the platform.
///
/// Production implementations must use storage whose monotonic state cannot
/// be rolled back together with journal bytes (for example a TPM-backed
/// monotonic/NV protocol or an equivalent platform root of trust). Ordinary
/// files do not satisfy this contract.
pub trait TrustedAnchorBackend {
    /// Backend-specific failure.
    type Error;

    /// Validates `binding` and atomically reserves a fresh recovery epoch.
    ///
    /// `observed_device` is the generation established by the platform's
    /// boot-time device quarantine/reset protocol. It must not be older than
    /// either the committed or previously issued device generation.
    fn reserve_recovery_epoch(
        &mut self,
        binding: RecoveryBinding,
        observed_device: crate::DeviceGeneration,
    ) -> Result<RecoveryLease, Self::Error>;

    /// Atomically compare-and-advances the protected journal tip.
    ///
    /// The replacement must become durable as one indivisible update. The
    /// backend must reject a stale `expected` tip. An error may mean that the
    /// advance became durable but its acknowledgement was lost.
    fn compare_and_advance(
        &mut self,
        expected: TrustedAnchorSnapshot,
        replacement: TrustedAnchorSnapshot,
    ) -> Result<(), Self::Error>;
}

/// Explicit trusted-anchor capability for changing only the catalog-set
/// digest of an existing recovery domain.
pub trait CatalogEvolutionAnchorBackend: TrustedAnchorBackend {
    /// Atomically advances the exact old tip to a same-world, same-Registry
    /// replacement carrying a different catalog-set digest.
    fn compare_and_rebind_catalog(
        &mut self,
        expected: TrustedAnchorSnapshot,
        replacement: TrustedAnchorSnapshot,
    ) -> Result<(), Self::Error>;
}

#[cfg(not(feature = "test-support"))]
mod authority_durability_seal {
    pub trait Sealed {}
}

/// Trusted durable-transition boundary consumed by [`crate::Engine`].
///
/// Production callers cannot implement this trait directly. Custom journal
/// and trusted-anchor backends implement [`DurableJournalBackend`] and
/// [`TrustedAnchorBackend`] and are then composed through
/// [`CoordinatedPersistence`], which is the sole production implementation.
/// With the explicit `test-support` feature, development fixtures may
/// implement this trait to exercise failure boundaries without platform
/// storage.
#[cfg(not(feature = "test-support"))]
pub trait TransitionDurability: authority_durability_seal::Sealed {
    /// Persistence failure returned to the engine.
    type Error;

    /// Makes a record and its resulting freshness durably authoritative.
    fn persist_transition(
        &mut self,
        record: &JournalRecord,
        resulting_freshness: Freshness,
        resulting_projection: Digest,
    ) -> Result<(), Self::Error>;
}

/// Development durability boundary consumed by [`crate::Engine`].
///
/// This form exists only with the explicit `test-support` feature. Production
/// builds expose the sealed contract documented above.
#[cfg(feature = "test-support")]
pub trait TransitionDurability {
    /// Persistence failure returned to the engine.
    type Error;

    /// Makes a record and its resulting freshness durably authoritative.
    fn persist_transition(
        &mut self,
        record: &JournalRecord,
        resulting_freshness: Freshness,
        resulting_projection: Digest,
    ) -> Result<(), Self::Error>;
}

#[cfg(not(feature = "test-support"))]
impl<J, A> authority_durability_seal::Sealed for CoordinatedPersistence<J, A> {}

/// Journal staging capability for the canonical streaming checkpoint path.
///
/// A backend writes the complete J10 record supplied by
/// [`CheckpointRecordPlan::write_to`] into inactive or otherwise recoverable
/// storage during [`Self::stage_checkpoint`].  Staging also selects all
/// in-memory candidate ownership needed by recovery; there is deliberately no
/// post-anchor callback which could allocate, fail, or drop a large image.
pub trait StreamingJournalBackend {
    /// Backend-specific failure from staging.
    type Error;

    /// Streams one exact J10 checkpoint record into inactive durable storage
    /// and selects the candidate that recovery will observe after anchoring.
    /// The backend must retain all ownership needed by that candidate before
    /// returning; no callback runs after the trusted anchor advances.
    fn stage_checkpoint(&mut self, plan: &CheckpointRecordPlan) -> Result<(), Self::Error>;
}

/// Trusted durability boundary for a canonical streaming checkpoint.
///
/// Production callers cannot implement this trait directly. Custom storage
/// participates through [`StreamingJournalBackend`] and
/// [`TrustedAnchorBackend`] composed by [`CoordinatedPersistence`].
#[cfg(not(feature = "test-support"))]
pub trait CheckpointDurability: authority_durability_seal::Sealed {
    /// Persistence failure returned to the engine.
    type Error;

    /// Stages the already prepared checkpoint without advancing the trusted
    /// anchor.  The prepared value can only originate from
    /// [`crate::Engine::checkpoint_prepare`], which arms the engine recovery latch.
    fn persist_checkpoint(&mut self, prepared: &PreparedCheckpoint) -> Result<(), Self::Error>;

    /// Advances the trusted anchor for the sealed checkpoint candidate.  The
    /// anchor is opaque and can only be minted from a prepared checkpoint by
    /// the core publication path; callers cannot supply arbitrary revision,
    /// freshness, projection, or digest metadata.
    fn anchor_checkpoint(&mut self, anchor: CheckpointAnchor) -> Result<(), Self::Error>;
}

/// Development durability boundary for a canonical streaming checkpoint.
///
/// This form exists only with the explicit `test-support` feature.
#[cfg(feature = "test-support")]
pub trait CheckpointDurability {
    /// Persistence failure returned to the engine.
    type Error;

    /// Stages the already prepared checkpoint without advancing the trusted
    /// anchor.  The prepared value can only originate from
    /// [`crate::Engine::checkpoint_prepare`], which arms the engine recovery latch.
    fn persist_checkpoint(&mut self, prepared: &PreparedCheckpoint) -> Result<(), Self::Error>;

    /// Advances the trusted anchor for the sealed checkpoint candidate.  The
    /// anchor is opaque and can only be minted from a prepared checkpoint by
    /// the core publication path; callers cannot supply arbitrary revision,
    /// freshness, projection, or digest metadata.
    fn anchor_checkpoint(&mut self, anchor: CheckpointAnchor) -> Result<(), Self::Error>;
}

/// Dedicated durability boundary for an append-only catalog-set checkpoint
/// rebind.
#[cfg(not(feature = "test-support"))]
pub trait CatalogEvolutionDurability: authority_durability_seal::Sealed {
    /// Persistence failure returned to the engine.
    type Error;
    /// Stages the sealed whole-state checkpoint under the evolved catalog set.
    fn persist_catalog_evolution(
        &mut self,
        prepared: &PreparedCheckpoint,
    ) -> Result<(), Self::Error>;
    /// Atomically rebinds the trusted anchor and selects the staged image.
    fn anchor_catalog_evolution(&mut self, anchor: CheckpointAnchor) -> Result<(), Self::Error>;
}

/// Development form of [`CatalogEvolutionDurability`].
#[cfg(feature = "test-support")]
pub trait CatalogEvolutionDurability {
    /// Persistence failure returned to the engine.
    type Error;
    /// Stages the sealed whole-state checkpoint under the evolved catalog set.
    fn persist_catalog_evolution(
        &mut self,
        prepared: &PreparedCheckpoint,
    ) -> Result<(), Self::Error>;
    /// Atomically rebinds the trusted anchor and selects the staged image.
    fn anchor_catalog_evolution(&mut self, anchor: CheckpointAnchor) -> Result<(), Self::Error>;
}

/// Failure from the ordered journal-plus-anchor protocol.
#[derive(Debug, Eq, PartialEq)]
pub enum CoordinatedPersistenceError<J, A> {
    /// Portable precondition failed before storage mutation.
    Protocol(PersistenceProtocolError),
    /// Journal append or durability barrier failed ambiguously.
    Journal(J),
    /// Trusted-anchor compare-and-advance failed ambiguously.
    Anchor(A),
}

/// Ordered journal and trusted-anchor transition coordinator.
#[derive(Debug)]
pub struct CoordinatedPersistence<J, A> {
    journal: J,
    anchor: A,
    committed: TrustedAnchorSnapshot,
    reserved_recovery: Option<Freshness>,
    committed_checkpoint: Option<JournalRecord>,
    recovery_required: bool,
}

impl<J, A> CoordinatedPersistence<J, A> {
    /// Binds backends to the exact lease used for core recovery.
    ///
    /// Call this before consuming the same lease into
    /// [`RecoveryLease::into_recovery_anchor`].
    pub fn from_recovery_lease(journal: J, anchor: A, lease: &RecoveryLease) -> Self {
        Self {
            journal,
            anchor,
            committed: lease.committed(),
            reserved_recovery: Some(lease.next_freshness()),
            committed_checkpoint: None,
            recovery_required: false,
        }
    }

    /// Returns the currently acknowledged trusted tip.
    pub const fn committed(&self) -> TrustedAnchorSnapshot {
        self.committed
    }

    /// Returns whether an ambiguous error requires drop and anchored reopen.
    pub const fn recovery_required(&self) -> bool {
        self.recovery_required
    }

    /// Returns shared access to the journal backend.
    pub const fn journal(&self) -> &J {
        &self.journal
    }

    /// Returns shared access to the trusted-anchor backend for diagnostics.
    ///
    /// This does not expose either mutable epoch reservation or tip
    /// advancement; those remain ordered through this coordinator.
    pub const fn anchor(&self) -> &A {
        &self.anchor
    }

    /// Runs one bounded, caller-supplied observation while the coordinator is
    /// already exclusively borrowed.  Kernel embeddings use this only for
    /// diagnostics around a compaction boundary; it is not an authority to
    /// publish a transition outside [`TransitionDurability`].
    pub fn inspect_journal<R>(&mut self, inspect: impl FnOnce(&mut J) -> R) -> R {
        inspect(&mut self.journal)
    }

    /// Consumes the coordinator into its backends.
    pub fn into_backends(self) -> (J, A) {
        (self.journal, self.anchor)
    }
}

impl<J, A> CoordinatedPersistence<J, A>
where
    J: CompactingJournalBackend,
    A: TrustedAnchorBackend,
{
    /// Replaces the durable replay image with the most recently anchored
    /// whole-state checkpoint, without advancing the trusted anchor.
    ///
    /// Only [`Self::persist_transition`] can populate the cached record, and
    /// it does so after the anchor acknowledges the checkpoint. Any later
    /// ordinary transition clears the cache, so this can never compact a
    /// suffix that is no longer the trusted tip.
    pub fn replace_last_committed_checkpoint(
        &mut self,
    ) -> Result<(), CoordinatedPersistenceError<J::Error, A::Error>> {
        if self.recovery_required {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::RecoveryRequired,
            ));
        }
        let checkpoint =
            self.committed_checkpoint
                .as_ref()
                .ok_or(CoordinatedPersistenceError::Protocol(
                    PersistenceProtocolError::NoCommittedCheckpoint,
                ))?;
        if checkpoint.bytes().len() > self.journal.checkpoint_capacity_bytes() {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::CheckpointTooLarge,
            ));
        }
        if checkpoint.revision() != self.committed.revision()
            || checkpoint.digest() != self.committed.head()
            || !checkpoint.is_whole_state_checkpoint()
            || !matches!(
                checkpoint.command(),
                crate::engine::CommandKind::WholeStateCheckpointV1 { projection, .. }
                    if *projection == checkpoint.base_projection()
            )
        {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleJournalHead,
            ));
        }

        self.recovery_required = true;
        self.journal
            .replace_with_checkpoint(checkpoint)
            .map_err(CoordinatedPersistenceError::Journal)?;
        self.committed_checkpoint = None;
        self.recovery_required = false;
        Ok(())
    }
}

impl<J, A> TransitionDurability for CoordinatedPersistence<J, A>
where
    J: DurableJournalBackend,
    A: TrustedAnchorBackend,
{
    type Error = CoordinatedPersistenceError<J::Error, A::Error>;

    fn persist_transition(
        &mut self,
        record: &JournalRecord,
        resulting_freshness: Freshness,
        resulting_projection: Digest,
    ) -> Result<(), Self::Error> {
        if self.recovery_required {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::RecoveryRequired,
            ));
        }
        // `JournalRecord::build` establishes this relation for records
        // prepared by the core, but the coordinator is also the final
        // authority boundary for records supplied by a recovery/backend
        // adapter.  Check the record's internal relation before any backend
        // call or recovery latch so a checksum-valid tampered record cannot
        // advance the anchor (or leave this instance poisoned).
        if record.base_revision().checked_add(1) != Some(record.revision()) {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleJournalHead,
            ));
        }
        let expected_freshness = self.committed.committed_freshness();
        if record.base_revision() != self.committed.revision()
            || record.predecessor() != self.committed.head()
            || record.base_projection() != self.committed.projection()
            || record.recovery_binding() != self.committed.binding()
            || record.boot() != expected_freshness.boot()
            || record.journal() != expected_freshness.journal()
            || record.device() != expected_freshness.device()
        {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleJournalHead,
            ));
        }
        if match self.reserved_recovery {
            Some(reserved) => {
                resulting_freshness != reserved
                    || !matches!(
                        record.command(),
                        crate::engine::CommandKind::CheckpointRecovery {
                            boot,
                            journal,
                            device,
                        } if *boot == reserved.boot()
                            && *journal == reserved.journal()
                            && *device == reserved.device()
                    )
            }
            None => resulting_freshness != expected_freshness,
        } {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleFreshness,
            ));
        }
        let replacement = TrustedAnchorSnapshot::from_trusted_backend(
            self.committed.binding(),
            resulting_freshness,
            record.revision(),
            record.digest(),
            resulting_projection,
        )
        .map_err(CoordinatedPersistenceError::Protocol)?;

        // A whole-state checkpoint may own up to the configured checkpoint
        // limit. Acquire the coordinator's replacement before crossing either
        // durability boundary. Its immutable image and encoded bytes are
        // Arc-backed, so this clone only retains those buffers; keeping the
        // ownership acquisition before append/anchor also preserves the
        // post-anchor assignment-only publication suffix.
        let committed_checkpoint = record.is_whole_state_checkpoint().then(|| record.clone());

        // Replace the cached replay image before entering the ambiguous
        // append/anchor boundary.  Assignment after anchor would release the
        // previous checkpoint's potentially large Arc-backed record in the
        // post-anchor suffix.
        let retired_checkpoint =
            core::mem::replace(&mut self.committed_checkpoint, committed_checkpoint);
        drop(retired_checkpoint);

        self.recovery_required = true;
        self.journal
            .append_and_sync(record)
            .map_err(CoordinatedPersistenceError::Journal)?;
        self.anchor
            .compare_and_advance(self.committed, replacement)
            .map_err(CoordinatedPersistenceError::Anchor)?;
        self.committed = replacement;
        if self.reserved_recovery == Some(resulting_freshness) {
            self.reserved_recovery = None;
        }
        self.recovery_required = false;
        Ok(())
    }
}

impl<J, A> CheckpointDurability for CoordinatedPersistence<J, A>
where
    J: StreamingJournalBackend,
    A: TrustedAnchorBackend,
{
    type Error = CoordinatedPersistenceError<J::Error, A::Error>;

    fn persist_checkpoint(&mut self, prepared: &PreparedCheckpoint) -> Result<(), Self::Error> {
        if self.recovery_required {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::RecoveryRequired,
            ));
        }
        // Streaming checkpoints cannot consume a recovery lease: only the
        // exact CheckpointRecovery transition can establish the reserved
        // epoch. Reject an old engine before it stages any durable candidate.
        if self.reserved_recovery.is_some() {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleFreshness,
            ));
        }
        let plan = prepared.plan();
        let expected_freshness = self.committed.committed_freshness();
        if plan.base_revision() != self.committed.revision()
            || plan.predecessor() != self.committed.head()
            || plan.base_projection() != self.committed.projection()
            || plan.binding() != self.committed.binding()
            || plan.freshness() != expected_freshness
        {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleJournalHead,
            ));
        }

        // An old append-path checkpoint cache is not part of this protocol and
        // must be released before the ambiguous stage/anchor boundary.  This
        // keeps the suffix after anchor advancement assignment-only.  The
        // journal backend owns all staged candidate storage before returning.
        self.committed_checkpoint = None;
        self.recovery_required = true;
        self.journal
            .stage_checkpoint(plan)
            .map_err(CoordinatedPersistenceError::Journal)?;
        Ok(())
    }

    fn anchor_checkpoint(&mut self, anchor: CheckpointAnchor) -> Result<(), Self::Error> {
        if !self.recovery_required {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::RecoveryRequired,
            ));
        }
        let expected_freshness = self.committed.committed_freshness();
        if anchor.base_revision() != self.committed.revision()
            || anchor.predecessor() != self.committed.head()
            || anchor.base_projection() != self.committed.projection()
            || anchor.binding() != self.committed.binding()
            || anchor.freshness() != expected_freshness
        {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleJournalHead,
            ));
        }
        if self.reserved_recovery.is_some() || anchor.resulting_freshness() != expected_freshness {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleFreshness,
            ));
        }
        let replacement = TrustedAnchorSnapshot::from_trusted_backend(
            self.committed.binding(),
            anchor.resulting_freshness(),
            anchor.revision(),
            anchor.digest(),
            anchor.resulting_projection(),
        )
        .map_err(CoordinatedPersistenceError::Protocol)?;
        self.anchor
            .compare_and_advance(self.committed, replacement)
            .map_err(CoordinatedPersistenceError::Anchor)?;

        // No callback, hash, allocation, fallible check, or checkpoint-sized
        // drop occurs after trusted-anchor advancement.
        self.committed = replacement;
        if self.reserved_recovery == Some(anchor.resulting_freshness()) {
            self.reserved_recovery = None;
        }
        self.recovery_required = false;
        Ok(())
    }
}

impl<J, A> CatalogEvolutionDurability for CoordinatedPersistence<J, A>
where
    J: StreamingJournalBackend,
    A: CatalogEvolutionAnchorBackend,
{
    type Error = CoordinatedPersistenceError<J::Error, A::Error>;

    fn persist_catalog_evolution(
        &mut self,
        prepared: &PreparedCheckpoint,
    ) -> Result<(), Self::Error> {
        if self.recovery_required {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::RecoveryRequired,
            ));
        }
        if self.reserved_recovery.is_some() {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleFreshness,
            ));
        }
        let plan = prepared.plan();
        let source = self.committed.binding();
        let target = plan.binding();
        if !plan.is_catalog_evolution()
            || plan.base_revision() != self.committed.revision()
            || plan.predecessor() != self.committed.head()
            || plan.durability_base_projection() != self.committed.projection()
            || plan.durability_catalog_digest() != source.catalog_digest()
            || target.catalog_digest() == source.catalog_digest()
            || target.profile() != source.profile()
            || target.world() != source.world()
            || target.registry() != source.registry()
            || plan.freshness() != self.committed.committed_freshness()
        {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::BindingMismatch,
            ));
        }
        self.committed_checkpoint = None;
        self.recovery_required = true;
        self.journal
            .stage_checkpoint(plan)
            .map_err(CoordinatedPersistenceError::Journal)
    }

    fn anchor_catalog_evolution(&mut self, anchor: CheckpointAnchor) -> Result<(), Self::Error> {
        if !self.recovery_required {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::RecoveryRequired,
            ));
        }
        let source = self.committed.binding();
        let target = anchor.binding();
        let expected_freshness = self.committed.committed_freshness();
        if anchor.predecessor_binding() != source
            || target.catalog_digest() == source.catalog_digest()
            || target.profile() != source.profile()
            || target.world() != source.world()
            || target.registry() != source.registry()
            || anchor.base_revision() != self.committed.revision()
            || anchor.predecessor() != self.committed.head()
            || anchor.base_projection() != self.committed.projection()
            || anchor.freshness() != expected_freshness
            || anchor.resulting_freshness() != expected_freshness
            || self.reserved_recovery.is_some()
        {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::BindingMismatch,
            ));
        }
        let replacement = TrustedAnchorSnapshot::from_trusted_backend(
            target,
            anchor.resulting_freshness(),
            anchor.revision(),
            anchor.digest(),
            anchor.resulting_projection(),
        )
        .map_err(CoordinatedPersistenceError::Protocol)?;
        self.anchor
            .compare_and_rebind_catalog(self.committed, replacement)
            .map_err(CoordinatedPersistenceError::Anchor)?;
        self.committed = replacement;
        self.recovery_required = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{
        BootGeneration, CatalogSet, CoreLimits, DeviceGeneration, Engine, JournalGeneration,
        RegistryInstance, standard_catalog, tool_dma_catalog,
    };

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        Replace,
        Anchor,
    }

    #[derive(Debug)]
    struct TestJournal {
        records: Vec<JournalRecord>,
        replacements: usize,
        fail_replacement: bool,
        checkpoint_capacity: usize,
    }

    impl DurableJournalBackend for TestJournal {
        type Error = TestError;

        fn append_and_sync(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
            self.records.push(record.clone());
            Ok(())
        }
    }

    impl CompactingJournalBackend for TestJournal {
        fn checkpoint_capacity_bytes(&self) -> usize {
            self.checkpoint_capacity
        }

        fn replace_with_checkpoint(
            &mut self,
            checkpoint: &JournalRecord,
        ) -> Result<(), Self::Error> {
            self.replacements += 1;
            if self.fail_replacement {
                return Err(TestError::Replace);
            }
            self.records.clear();
            self.records.push(checkpoint.clone());
            Ok(())
        }
    }

    #[derive(Debug)]
    struct TestAnchor {
        committed: TrustedAnchorSnapshot,
    }

    impl TrustedAnchorBackend for TestAnchor {
        type Error = TestError;

        fn reserve_recovery_epoch(
            &mut self,
            _binding: RecoveryBinding,
            _observed_device: crate::DeviceGeneration,
        ) -> Result<RecoveryLease, Self::Error> {
            Err(TestError::Anchor)
        }

        fn compare_and_advance(
            &mut self,
            expected: TrustedAnchorSnapshot,
            replacement: TrustedAnchorSnapshot,
        ) -> Result<(), Self::Error> {
            if expected != self.committed {
                return Err(TestError::Anchor);
            }
            self.committed = replacement;
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StreamingTestError {
        Stage,
        Anchor,
        Write,
    }

    #[derive(Debug, Default)]
    struct StreamingTestJournal {
        staged: Vec<u8>,
        fail_stage: bool,
    }

    impl StreamingJournalBackend for StreamingTestJournal {
        type Error = StreamingTestError;

        fn stage_checkpoint(&mut self, plan: &CheckpointRecordPlan) -> Result<(), Self::Error> {
            if self.fail_stage {
                return Err(StreamingTestError::Stage);
            }
            self.staged.clear();
            plan.write_to(&mut self.staged)
                .map_err(|_| StreamingTestError::Write)?;
            Ok(())
        }
    }

    #[derive(Debug)]
    struct StreamingTestAnchor {
        committed: TrustedAnchorSnapshot,
        fail_advance: bool,
    }

    impl TrustedAnchorBackend for StreamingTestAnchor {
        type Error = StreamingTestError;

        fn reserve_recovery_epoch(
            &mut self,
            _binding: RecoveryBinding,
            _observed_device: crate::DeviceGeneration,
        ) -> Result<RecoveryLease, Self::Error> {
            Err(StreamingTestError::Anchor)
        }

        fn compare_and_advance(
            &mut self,
            expected: TrustedAnchorSnapshot,
            replacement: TrustedAnchorSnapshot,
        ) -> Result<(), Self::Error> {
            if self.fail_advance {
                return Err(StreamingTestError::Anchor);
            }
            if expected != self.committed {
                return Err(StreamingTestError::Anchor);
            }
            self.committed = replacement;
            Ok(())
        }
    }

    impl CatalogEvolutionAnchorBackend for StreamingTestAnchor {
        fn compare_and_rebind_catalog(
            &mut self,
            expected: TrustedAnchorSnapshot,
            replacement: TrustedAnchorSnapshot,
        ) -> Result<(), Self::Error> {
            if self.fail_advance || expected != self.committed {
                return Err(StreamingTestError::Anchor);
            }
            let source = expected.binding();
            let target = replacement.binding();
            if target.catalog_digest() == source.catalog_digest()
                || target.profile() != source.profile()
                || target.world() != source.world()
                || target.registry() != source.registry()
            {
                return Err(StreamingTestError::Anchor);
            }
            self.committed = replacement;
            Ok(())
        }
    }

    fn freshness(boot: u64) -> Freshness {
        Freshness::new(
            BootGeneration::new(boot).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(boot).unwrap(),
        )
    }

    fn coordinator(
        fail_replacement: bool,
    ) -> (Engine, CoordinatedPersistence<TestJournal, TestAnchor>) {
        let catalog = standard_catalog();
        let catalog_set = CatalogSet::new(core::slice::from_ref(&catalog)).unwrap();
        let engine = Engine::new(
            crate::WorldId::new(1).unwrap(),
            catalog_set.clone(),
            CoreLimits::bounded_default(),
            freshness(1),
        );
        let binding = RecoveryBinding::new(
            RecoveryProfile::current(),
            crate::WorldId::new(1).unwrap(),
            catalog_set.digest(),
            RegistryInstance::new(1).unwrap(),
        )
        .unwrap();
        let committed = TrustedAnchorSnapshot::from_trusted_backend(
            binding,
            freshness(1),
            0,
            Digest::ZERO,
            engine.projection_digest(),
        )
        .unwrap();
        let lease = RecoveryLease::from_trusted_backend(committed, freshness(2)).unwrap();
        let mut persistence = CoordinatedPersistence::from_recovery_lease(
            TestJournal {
                records: Vec::new(),
                replacements: 0,
                fail_replacement,
                checkpoint_capacity: usize::MAX,
            },
            TestAnchor { committed },
            &lease,
        );
        // Most tests below exercise steady-state persistence after the boot's
        // recovery checkpoint has already consumed its lease.
        persistence.reserved_recovery = None;
        (engine, persistence)
    }

    fn streaming_coordinator(
        fail_stage: bool,
        fail_advance: bool,
    ) -> (
        Engine,
        CoordinatedPersistence<StreamingTestJournal, StreamingTestAnchor>,
    ) {
        let catalog = standard_catalog();
        let catalog_set = CatalogSet::new(core::slice::from_ref(&catalog)).unwrap();
        let engine = Engine::new(
            crate::WorldId::new(1).unwrap(),
            catalog_set.clone(),
            CoreLimits::bounded_default(),
            freshness(1),
        );
        let binding = RecoveryBinding::new(
            RecoveryProfile::current(),
            crate::WorldId::new(1).unwrap(),
            catalog_set.digest(),
            RegistryInstance::new(1).unwrap(),
        )
        .unwrap();
        let committed = TrustedAnchorSnapshot::from_trusted_backend(
            binding,
            freshness(1),
            0,
            Digest::ZERO,
            engine.projection_digest(),
        )
        .unwrap();
        let lease = RecoveryLease::from_trusted_backend(committed, freshness(2)).unwrap();
        let mut persistence = CoordinatedPersistence::from_recovery_lease(
            StreamingTestJournal {
                fail_stage,
                ..StreamingTestJournal::default()
            },
            StreamingTestAnchor {
                committed,
                fail_advance,
            },
            &lease,
        );
        // Most streaming tests exercise steady-state checkpointing after the
        // boot's recovery checkpoint has already consumed its lease.
        persistence.reserved_recovery = None;
        (engine, persistence)
    }

    #[test]
    fn reserved_recovery_epoch_fences_old_engine_until_exact_commit() {
        let (mut engine, mut persistence) = coordinator(false);
        persistence.reserved_recovery = Some(freshness(2));

        let error = engine.compact_checkpoint_durable(&mut persistence);
        assert!(matches!(
            error,
            Err(crate::TxError::Persist(
                CoordinatedPersistenceError::Protocol(PersistenceProtocolError::StaleFreshness)
            ))
        ));
        assert!(persistence.journal.records.is_empty());
        assert!(!persistence.recovery_required());
        assert!(engine.persistence_recovery_required());

        let lease = RecoveryLease::from_trusted_backend(persistence.committed, freshness(2))
            .expect("reconstruct test lease");
        let mut recovered = Engine::recover(
            CatalogSet::new(&[standard_catalog()]).unwrap(),
            CoreLimits::bounded_default(),
            lease.into_recovery_anchor().unwrap(),
            &[],
        )
        .expect("recover a fresh engine under the lease")
        .into_engine();
        recovered
            .transact_durable(
                crate::CommandRequest::CheckpointRecovery {
                    boot: freshness(2).boot(),
                    journal: freshness(2).journal(),
                    device: freshness(2).device(),
                },
                &mut persistence,
            )
            .expect("the exact recovery transition consumes the lease");
        assert_eq!(persistence.committed.committed_freshness(), freshness(2));
        assert_eq!(persistence.reserved_recovery, None);

        recovered
            .compact_checkpoint_durable(&mut persistence)
            .expect("ordinary transitions resume after recovery commits");
    }

    #[test]
    fn reserved_epoch_rejects_a_nonmatching_recovery_record() {
        let (engine, mut persistence) = coordinator(false);
        persistence.reserved_recovery = Some(freshness(2));
        let record = JournalRecord::build(
            0,
            freshness(1),
            persistence.committed.binding(),
            engine.projection_digest(),
            Digest::ZERO,
            crate::engine::CommandKind::CheckpointRecovery {
                boot: freshness(3).boot(),
                journal: freshness(3).journal(),
                device: freshness(3).device(),
            },
        )
        .unwrap();

        assert_eq!(
            persistence.persist_transition(&record, freshness(2), engine.projection_digest()),
            Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleFreshness
            ))
        );
        assert!(persistence.journal.records.is_empty());
        assert!(!persistence.recovery_required());
    }

    #[test]
    fn coordinator_rejects_a_checksum_valid_revision_tamper_before_mutation() {
        let (engine, mut persistence) = coordinator(false);
        let record = JournalRecord::build(
            0,
            freshness(1),
            persistence.committed.binding(),
            engine.projection_digest(),
            Digest::ZERO,
            crate::engine::CommandKind::CheckpointRecovery {
                boot: BootGeneration::new(2).unwrap(),
                journal: JournalGeneration::new(2).unwrap(),
                device: DeviceGeneration::new(1).unwrap(),
            },
        )
        .unwrap()
        .with_revision_for_test(2);
        let committed = persistence.committed;

        assert_eq!(
            persistence.persist_transition(&record, freshness(1), engine.projection_digest()),
            Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleJournalHead
            ))
        );
        assert_eq!(persistence.committed, committed);
        assert!(persistence.journal.records.is_empty());
        assert!(!persistence.recovery_required());
    }

    #[test]
    fn anchored_checkpoint_replaces_only_after_journal_and_anchor_commit() {
        let (mut engine, mut persistence) = coordinator(false);
        let receipt = engine.compact_checkpoint_durable(&mut persistence).unwrap();
        assert_eq!(persistence.journal.records.len(), 1);
        assert_eq!(persistence.committed.revision(), receipt.revision());
        assert_eq!(persistence.committed.head(), receipt.head());
        let committed_clone = persistence.committed_checkpoint.as_ref().unwrap().clone();
        assert!(
            persistence
                .committed_checkpoint
                .as_ref()
                .unwrap()
                .shares_bytes_with(&committed_clone)
        );
        assert!(
            persistence
                .committed_checkpoint
                .as_ref()
                .unwrap()
                .shares_checkpoint_image_with(&committed_clone)
        );

        persistence.replace_last_committed_checkpoint().unwrap();
        assert_eq!(persistence.journal.replacements, 1);
        assert_eq!(persistence.journal.records.len(), 1);
        assert_eq!(persistence.journal.records[0].digest(), receipt.head());
        assert!(!persistence.recovery_required());
    }

    #[test]
    fn ordinary_or_missing_checkpoint_cannot_replace_the_replay_image() {
        let (_engine, mut persistence) = coordinator(false);
        assert_eq!(
            persistence.replace_last_committed_checkpoint(),
            Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::NoCommittedCheckpoint
            ))
        );
        assert_eq!(persistence.journal.replacements, 0);
        assert!(!persistence.recovery_required());
    }

    #[test]
    fn stale_cached_checkpoint_is_rejected_before_replacement_mutates_storage() {
        let (mut engine, mut persistence) = coordinator(false);
        engine.compact_checkpoint_durable(&mut persistence).unwrap();
        persistence.committed = TrustedAnchorSnapshot::from_trusted_backend(
            persistence.committed.binding(),
            persistence.committed.committed_freshness(),
            persistence.committed.revision() + 1,
            Digest::new([7; 32]),
            persistence.committed.projection(),
        )
        .unwrap();

        assert_eq!(
            persistence.replace_last_committed_checkpoint(),
            Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleJournalHead
            ))
        );
        assert_eq!(persistence.journal.replacements, 0);
        assert!(!persistence.recovery_required());
    }

    #[test]
    fn oversized_checkpoint_is_rejected_before_replacement_mutates_storage() {
        let (mut engine, mut persistence) = coordinator(false);
        engine.compact_checkpoint_durable(&mut persistence).unwrap();
        persistence.journal.checkpoint_capacity = 0;

        assert_eq!(
            persistence.replace_last_committed_checkpoint(),
            Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::CheckpointTooLarge
            ))
        );
        assert_eq!(persistence.journal.replacements, 0);
        assert!(!persistence.recovery_required());
    }

    #[test]
    fn replacement_failure_latches_recovery_required() {
        let (mut engine, mut persistence) = coordinator(true);
        let receipt = engine.compact_checkpoint_durable(&mut persistence).unwrap();
        assert_eq!(
            persistence.replace_last_committed_checkpoint(),
            Err(CoordinatedPersistenceError::Journal(TestError::Replace))
        );
        assert!(persistence.recovery_required());
        assert_eq!(persistence.journal.replacements, 1);
        assert_eq!(
            persistence.replace_last_committed_checkpoint(),
            Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::RecoveryRequired
            ))
        );
        assert_eq!(persistence.journal.replacements, 1);

        // The failed acknowledgement is ambiguous, but this fixture leaves
        // the anchored checkpoint append intact. A fresh coordinator must be
        // able to reopen that trusted prefix rather than continue in-place.
        let (journal, anchor) = persistence.into_backends();
        let mut bytes = Vec::new();
        for record in journal.records {
            bytes.extend_from_slice(record.bytes());
        }
        let recovered = Engine::recover(
            CatalogSet::new(&[standard_catalog()]).unwrap(),
            CoreLimits::bounded_default(),
            RecoveryAnchor::from_trusted_provider(
                anchor.committed.binding(),
                anchor.committed.committed_freshness(),
                freshness(2),
                anchor.committed.revision(),
                anchor.committed.head(),
                anchor.committed.projection(),
            )
            .unwrap(),
            &bytes,
        )
        .expect("anchored checkpoint reopens after replacement failure");
        assert_eq!(recovered.acknowledged_revision(), receipt.revision());
        assert_eq!(recovered.acknowledged_head(), receipt.head());
    }

    #[test]
    fn streaming_checkpoint_stages_anchors_then_publishes() {
        let (mut engine, mut persistence) = streaming_coordinator(false, false);
        let snapshot = engine.checkpoint_snapshot().unwrap();
        let plan = snapshot.prepare_plan().unwrap();
        let prepared = engine.checkpoint_prepare(plan).unwrap();
        let expected_digest = prepared.plan().digest();
        let expected_len = prepared.plan().record_len();
        let durable = prepared.persist_checkpoint(&mut persistence).unwrap();
        assert_eq!(persistence.journal().staged.len(), expected_len);
        assert_eq!(
            Digest::new(
                persistence.journal().staged[expected_len - 32..]
                    .try_into()
                    .unwrap()
            ),
            expected_digest
        );
        let receipt = engine
            .checkpoint_publish(durable, &mut persistence)
            .unwrap();
        assert_eq!(receipt.head(), expected_digest);
        assert!(!persistence.recovery_required());
        assert!(!engine.persistence_recovery_required());
    }

    #[test]
    fn streaming_checkpoint_stage_failure_latches_before_publication() {
        let (mut engine, mut persistence) = streaming_coordinator(true, false);
        let prepared = engine
            .checkpoint_prepare(
                engine
                    .checkpoint_snapshot()
                    .unwrap()
                    .prepare_plan()
                    .unwrap(),
            )
            .unwrap();
        let error = prepared.persist_checkpoint(&mut persistence);
        assert!(matches!(
            error,
            Err(crate::TxError::Persist(
                CoordinatedPersistenceError::Journal(StreamingTestError::Stage)
            ))
        ));
        assert!(persistence.recovery_required());
        assert!(engine.persistence_recovery_required());
        assert!(persistence.journal().staged.is_empty());
    }

    #[test]
    fn reserved_recovery_epoch_rejects_streaming_checkpoint_before_stage() {
        let (mut engine, mut persistence) = streaming_coordinator(false, false);
        persistence.reserved_recovery = Some(freshness(2));
        let prepared = engine
            .checkpoint_prepare(
                engine
                    .checkpoint_snapshot()
                    .unwrap()
                    .prepare_plan()
                    .unwrap(),
            )
            .unwrap();

        let error = prepared.persist_checkpoint(&mut persistence);
        assert!(matches!(
            error,
            Err(crate::TxError::Persist(
                CoordinatedPersistenceError::Protocol(PersistenceProtocolError::StaleFreshness)
            ))
        ));
        assert!(persistence.journal().staged.is_empty());
        assert!(!persistence.recovery_required());
        assert!(engine.persistence_recovery_required());
    }

    #[test]
    fn streaming_checkpoint_anchor_failure_latches_and_keeps_stage_private() {
        let (mut engine, mut persistence) = streaming_coordinator(false, true);
        let prepared = engine
            .checkpoint_prepare(
                engine
                    .checkpoint_snapshot()
                    .unwrap()
                    .prepare_plan()
                    .unwrap(),
            )
            .unwrap();
        let durable = prepared.persist_checkpoint(&mut persistence).unwrap();
        let error = engine.checkpoint_publish(durable, &mut persistence);
        assert!(matches!(
            error,
            Err(crate::TxError::Persist(
                CoordinatedPersistenceError::Anchor(StreamingTestError::Anchor)
            ))
        ));
        assert!(persistence.recovery_required());
        assert!(engine.persistence_recovery_required());
        assert!(!persistence.journal().staged.is_empty());
    }

    #[test]
    fn staged_checkpoint_cannot_publish_into_another_engine() {
        let (mut engine_a, mut persistence_a) = streaming_coordinator(false, false);
        let (mut engine_b, mut persistence_b) = streaming_coordinator(false, false);
        let prepared = engine_a
            .checkpoint_prepare(
                engine_a
                    .checkpoint_snapshot()
                    .unwrap()
                    .prepare_plan()
                    .unwrap(),
            )
            .unwrap();
        let durable = prepared.persist_checkpoint(&mut persistence_a).unwrap();

        let result = engine_b.checkpoint_publish(durable, &mut persistence_b);
        assert!(matches!(
            result,
            Err(crate::TxError::Core(crate::CoreError::InvariantViolation))
        ));
        assert!(!engine_b.persistence_recovery_required());
        assert!(!persistence_b.recovery_required());
        assert!(engine_a.persistence_recovery_required());
        assert!(persistence_a.recovery_required());
        assert!(persistence_b.journal().staged.is_empty());
    }

    #[test]
    fn catalog_evolution_uses_the_explicit_anchor_rebind_capability() {
        let (mut engine, mut persistence) = streaming_coordinator(false, false);
        let old_binding = persistence.committed().binding();
        let evolved = CatalogSet::new(&[standard_catalog(), tool_dma_catalog()]).unwrap();

        engine
            .evolve_catalog_set_streaming(evolved.clone(), &mut persistence)
            .unwrap();

        assert_eq!(engine.catalog_set_digest(), evolved.digest());
        assert_eq!(
            persistence.committed().binding().catalog_digest(),
            evolved.digest()
        );
        assert_ne!(persistence.committed().binding(), old_binding);
        assert!(!persistence.journal().staged.is_empty());
        assert!(!persistence.recovery_required());
    }
}
