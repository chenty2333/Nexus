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
    Digest, Freshness, JournalRecord, RecoveryAnchor, RecoveryAnchorError, RegistryInstance,
};

/// Stable schema and principal-binding coordinates expected at boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryBinding {
    catalog_digest: Digest,
    registry: RegistryInstance,
    binding: u64,
}

impl RecoveryBinding {
    /// Creates an exact recovery binding.
    pub const fn new(
        catalog_digest: Digest,
        registry: RegistryInstance,
        binding: u64,
    ) -> Result<Self, PersistenceProtocolError> {
        if catalog_digest.is_zero() || binding == 0 {
            return Err(PersistenceProtocolError::InvalidAnchor);
        }
        Ok(Self {
            catalog_digest,
            registry,
            binding,
        })
    }

    /// Returns the expected domain-catalog digest.
    pub const fn catalog_digest(self) -> Digest {
        self.catalog_digest
    }

    /// Returns the expected durable Registry identity.
    pub const fn registry(self) -> RegistryInstance {
        self.registry
    }

    /// Returns the expected principal-binding generation.
    pub const fn binding(self) -> u64 {
        self.binding
    }
}

/// Exact journal tip atomically protected by a trusted anchor backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedAnchorSnapshot {
    binding: RecoveryBinding,
    committed_freshness: Freshness,
    revision: u64,
    head: Digest,
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
    ) -> Result<Self, PersistenceProtocolError> {
        if committed_freshness.registry().get() != binding.registry().get()
            || committed_freshness.binding() != binding.binding()
        {
            return Err(PersistenceProtocolError::BindingMismatch);
        }
        if (revision == 0) != head.is_zero() {
            return Err(PersistenceProtocolError::InvalidAnchor);
        }
        Ok(Self {
            binding,
            committed_freshness,
            revision,
            head,
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
            committed.binding().catalog_digest(),
            committed.committed_freshness(),
            next_freshness,
            committed.revision(),
            committed.head(),
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
            self.committed.binding().catalog_digest(),
            self.committed.committed_freshness(),
            self.next_freshness,
            self.committed.revision(),
            self.committed.head(),
        )
    }
}

/// Portable protocol violation detected before a backend operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceProtocolError {
    /// A zero digest, zero binding, or inconsistent genesis coordinates were supplied.
    InvalidAnchor,
    /// Catalog, Registry, or principal-binding coordinates do not match.
    BindingMismatch,
    /// A record does not extend the exact trusted journal tip.
    StaleJournalHead,
    /// Resulting freshness is stale or was not reserved for this recovery.
    StaleFreshness,
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

/// Durable-transition boundary consumed by [`crate::Engine`].
pub trait TransitionDurability {
    /// Persistence failure returned to the engine.
    type Error;

    /// Makes a record and its resulting freshness durably authoritative.
    fn persist_transition(
        &mut self,
        record: &JournalRecord,
        resulting_freshness: Freshness,
    ) -> Result<(), Self::Error>;
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

    /// Consumes the coordinator into its backends.
    pub fn into_backends(self) -> (J, A) {
        (self.journal, self.anchor)
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
    ) -> Result<(), Self::Error> {
        if self.recovery_required {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::RecoveryRequired,
            ));
        }
        let expected_freshness = self.committed.committed_freshness();
        if record.base_revision() != self.committed.revision()
            || record.predecessor() != self.committed.head()
            || record.catalog_digest() != self.committed.binding().catalog_digest()
            || record.registry().get() != self.committed.binding().registry().get()
            || record.binding() != self.committed.binding().binding()
            || record.boot() != expected_freshness.boot()
            || record.journal() != expected_freshness.journal()
            || record.device() != expected_freshness.device()
        {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleJournalHead,
            ));
        }
        if resulting_freshness != expected_freshness
            && self.reserved_recovery != Some(resulting_freshness)
        {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::StaleFreshness,
            ));
        }
        let replacement = TrustedAnchorSnapshot::from_trusted_backend(
            self.committed.binding(),
            resulting_freshness,
            record.revision(),
            record.digest(),
        )
        .map_err(CoordinatedPersistenceError::Protocol)?;

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
