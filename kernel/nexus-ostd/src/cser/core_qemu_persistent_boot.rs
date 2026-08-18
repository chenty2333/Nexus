// SPDX-License-Identifier: MPL-2.0

//! QEMU-specific acquisition of the persistent CSER boot envelope.
//!
//! This module deliberately stops at the generic recovery boundary.  It owns
//! the physical preparation shared by the production and experiment profiles:
//! withholding the fixed DMA arena, inspecting the TPM tip, deriving the next
//! device generation, quarantining the real VirtIO device, and opening the
//! primary ATA journal.  It does not choose a catalog or advance any business
//! state.  Callers supply those at [`PreparedQemuPersistentBoot::recover`].

use cser_core::{
    CatalogSet, CoordinatedPersistence, CoreError, CoreLimits, DeviceGeneration, Digest,
    RecoveryBinding,
};
use nexus_ostd_virtio::{
    BootQuarantineGuard, BootQuarantineObservation, OwnerKind, PersistentDmaArenaLayout,
    install_persistent_dma_arena, qemu_hypervisor_detected,
};
use sha2::{Digest as _, Sha256};

use super::{
    core_device_quarantine::OstdVirtioBootQuarantine,
    core_dma_arena_allocator::{persistent_dma_arena_base, persistent_dma_arena_ready},
    core_pio_journal::{AtaJournalFixture, AtaPioJournal, AtaPioJournalVNext},
    core_reboot::{
        AlreadyQuarantined, BootDeviceQuarantine, BootRecoveryError, OstdBootJournal,
        QuarantinedRecoveredBoot, recover_quarantined_boot,
    },
    core_tpm_anchor::{
        QemuTisTpm2, TpmNvAnchorCandidate, TpmNvIndexAuth, TpmNvLayout, TpmNvTrustedAnchor,
    },
};

pub(crate) type QemuPersistentAnchor = TpmNvTrustedAnchor<QemuTisTpm2>;
pub(crate) type QemuPersistentDurability =
    CoordinatedPersistence<AtaPioJournal, QemuPersistentAnchor>;
pub(crate) type QemuPersistentBoot =
    QuarantinedRecoveredBoot<AtaPioJournal, QemuPersistentAnchor, BootQuarantineGuard>;
/// The fresh-media append/checkpoint journal selection.  It intentionally has
/// a distinct boot-envelope type so a vNext QEMU scheme cannot accidentally
/// reinterpret a legacy image.
pub(crate) type QemuPersistentBootVNext =
    QuarantinedRecoveredBoot<AtaPioJournalVNext, QemuPersistentAnchor, BootQuarantineGuard>;

/// The prepared ownership envelope before catalog-bound recovery.
///
/// The TPM candidate deliberately remains unbound here: selecting a catalog
/// is a caller decision, while inspecting the TPM and placing the device under
/// quarantine must happen before either production or an experiment can read
/// a durable journal prefix.
pub(crate) struct PreparedQemuPersistentBootFor<J> {
    arena: PersistentDmaArenaLayout,
    candidate: TpmNvAnchorCandidate<QemuTisTpm2>,
    journal: J,
    guard: BootQuarantineGuard,
}

pub(crate) type PreparedQemuPersistentBoot = PreparedQemuPersistentBootFor<AtaPioJournal>;
/// Prepared envelope for a blank vNext image.  This is deliberately parallel
/// to the legacy alias rather than a runtime format probe.
pub(crate) type PreparedQemuPersistentBootVNext = PreparedQemuPersistentBootFor<AtaPioJournalVNext>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum QemuPersistentBootError {
    ArenaNotWithheld,
    ArenaInstall,
    UnsupportedQemuProfile,
    TpmTransport,
    TpmAuth,
    TpmInspect,
    DeviceGenerationOverflow,
    DeviceGenerationInvalid,
    DeviceQuarantine,
    AtaJournalUnavailable,
    AtaJournalRead,
    CatalogBindingMismatch,
    AnchorBinding,
    RecoveryCore(CoreError),
    RecoveryCheckpoint,
    Recovery,
}

impl PreparedQemuPersistentBoot {
    /// Acquires all host/device durability providers without choosing a CSER
    /// catalog.  The caller owns the returned linear envelope and can consume
    /// it exactly once through [`Self::recover`].
    pub(crate) fn acquire() -> Result<Self, QemuPersistentBootError> {
        Self::acquire_with(|| AtaPioJournal::acquire(AtaJournalFixture::PrimaryMaster))
    }

    /// Enables the experiment-only, default-off provider counters before
    /// recovery consumes this linear boot envelope.
    pub(crate) fn set_diagnostic_telemetry(&mut self, enabled: bool) {
        self.journal.set_telemetry(enabled);
        self.candidate.set_telemetry(enabled);
    }
}

impl PreparedQemuPersistentBootVNext {
    /// Acquires the same QEMU devices as the legacy envelope, but opens the
    /// fresh append/checkpoint journal.  Callers must give it a separate blank
    /// artifact path; there is intentionally no migration or auto-detection.
    pub(crate) fn acquire() -> Result<Self, QemuPersistentBootError> {
        Self::acquire_with(|| AtaPioJournalVNext::acquire(AtaJournalFixture::PrimaryMaster))
    }

    /// Enables the experiment-only, default-off provider counters before
    /// recovery consumes this linear boot envelope.
    pub(crate) fn set_diagnostic_telemetry(&mut self, enabled: bool) {
        self.journal.set_telemetry(enabled);
        self.candidate.set_telemetry(enabled);
    }
}

impl<J> PreparedQemuPersistentBootFor<J>
where
    J: OstdBootJournal,
{
    fn acquire_with<F>(journal: F) -> Result<Self, QemuPersistentBootError>
    where
        F: FnOnce() -> Result<J, super::core_pio_journal::AtaPioJournalError>,
    {
        if !persistent_dma_arena_ready() {
            return Err(QemuPersistentBootError::ArenaNotWithheld);
        }
        let arena = install_persistent_dma_arena(persistent_dma_arena_base())
            .map_err(|_| QemuPersistentBootError::ArenaInstall)?;
        if arena.paddr_base() != persistent_dma_arena_base()
            || arena.page_count() != 3
            || !qemu_hypervisor_detected()
        {
            return Err(QemuPersistentBootError::UnsupportedQemuProfile);
        }

        let transport = QemuTisTpm2::acquire_qemu_fixture()
            .map_err(|_| QemuPersistentBootError::TpmTransport)?;
        let auth = TpmNvIndexAuth::new(&[]).map_err(|_| QemuPersistentBootError::TpmAuth)?;
        let candidate = TpmNvTrustedAnchor::inspect(transport, TpmNvLayout::qemu_fixture(), auth)
            .map_err(|_| QemuPersistentBootError::TpmInspect)?;
        let high_water = candidate
            .committed()
            .committed_freshness()
            .device()
            .get()
            .max(candidate.issued().device().get());
        let next = high_water
            .checked_add(1)
            .ok_or(QemuPersistentBootError::DeviceGenerationOverflow)?;
        let observed_generation = DeviceGeneration::new(next)
            .map_err(|_| QemuPersistentBootError::DeviceGenerationInvalid)?;
        let (guard, journal) = quarantine_before_journal(
            || {
                OstdVirtioBootQuarantine::new(observed_generation)
                    .quarantine_all()
                    .map_err(|_| QemuPersistentBootError::DeviceQuarantine)
            },
            || journal().map_err(|_| QemuPersistentBootError::AtaJournalUnavailable),
        )?;
        Ok(Self {
            arena,
            candidate,
            journal,
            guard,
        })
    }

    pub(crate) const fn arena(&self) -> PersistentDmaArenaLayout {
        self.arena
    }

    /// Returns whether every validated physical candidate carries the frozen
    /// schema-8 prefix. The probe reads only the fixed magic and revalidates
    /// each candidate; it never selects by physical generation or materializes
    /// a journal image. Mixed old/current candidates remain ambiguous and fall
    /// through to ordinary anchored recovery, which fails closed.
    pub(crate) fn journal_is_unambiguously_schema8(
        &mut self,
    ) -> Result<bool, QemuPersistentBootError> {
        const SCHEMA8_MAGIC: [u8; 8] = *b"CSERJR8\0";

        let candidates = self
            .journal
            .recovery_candidates()
            .map_err(|_| QemuPersistentBootError::AtaJournalRead)?;
        if candidates.is_empty() {
            return Ok(false);
        }
        for candidate in candidates {
            if candidate.logical_len() < SCHEMA8_MAGIC.len() {
                return Ok(false);
            }
            let mut magic = [0u8; 8];
            self.journal
                .read_recovery_at(candidate, 0, &mut magic)
                .map_err(|_| QemuPersistentBootError::AtaJournalRead)?;
            self.journal
                .revalidate_recovery_candidate(candidate)
                .map_err(|_| QemuPersistentBootError::AtaJournalRead)?;
            if magic != SCHEMA8_MAGIC {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) const fn candidate(&self) -> &TpmNvAnchorCandidate<QemuTisTpm2> {
        &self.candidate
    }

    pub(crate) const fn quarantine_observation(&self) -> BootQuarantineObservation {
        self.guard.observation()
    }

    /// Binds the previously inspected TPM state to an explicitly supplied
    /// catalog and recovers through the same quarantine-preserving routine as
    /// production.  No experiment is allowed to substitute an in-memory
    /// journal or bypass this binding step.
    pub(crate) fn recover(
        self,
        catalogs: CatalogSet,
        limits: CoreLimits,
        binding: RecoveryBinding,
    ) -> Result<
        QuarantinedRecoveredBoot<J, QemuPersistentAnchor, BootQuarantineGuard>,
        QemuPersistentBootError,
    > {
        if catalogs.digest() != binding.catalog_digest() {
            return Err(QemuPersistentBootError::CatalogBindingMismatch);
        }
        let anchor = self
            .candidate
            .bind(binding)
            .map_err(|_| QemuPersistentBootError::AnchorBinding)?;
        recover_quarantined_boot(
            catalogs,
            limits,
            binding,
            self.journal,
            anchor,
            AlreadyQuarantined::new(self.guard),
        )
        .map_err(|error| match error {
            BootRecoveryError::Core(error) => QemuPersistentBootError::RecoveryCore(error),
            BootRecoveryError::Checkpoint(_) => QemuPersistentBootError::RecoveryCheckpoint,
            _ => QemuPersistentBootError::Recovery,
        })
    }
}

/// Keeps the physical fence and the first durable-journal read in a single,
/// auditable sequence. Both operations are closures deliberately: passing a
/// pre-evaluated journal result here would reintroduce Rust's argument
/// evaluation-order hazard and let a bank read happen before quarantine.
fn quarantine_before_journal<Q, J, FQ, FJ>(
    quarantine: FQ,
    journal: FJ,
) -> Result<(Q, J), QemuPersistentBootError>
where
    FQ: FnOnce() -> Result<Q, QemuPersistentBootError>,
    FJ: FnOnce() -> Result<J, QemuPersistentBootError>,
{
    let guard = quarantine()?;
    let journal = journal()?;
    Ok((guard, journal))
}

#[cfg(ktest)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use ostd::prelude::ktest;

    #[ktest]
    fn physical_quarantine_completes_before_first_journal_read() {
        let events = RefCell::new(Vec::new());
        let (guard, journal) = quarantine_before_journal(
            || {
                events.borrow_mut().push("quarantine-complete");
                Ok::<_, QemuPersistentBootError>(())
            },
            || {
                events.borrow_mut().push("journal-first-read");
                Ok::<_, QemuPersistentBootError>(())
            },
        )
        .expect("test acquisition sequence succeeds");

        assert_eq!((guard, journal), ((), ()));
        assert_eq!(
            events.into_inner(),
            ["quarantine-complete", "journal-first-read"]
        );
    }

    #[ktest]
    fn journal_is_not_opened_when_physical_quarantine_fails() {
        let events = RefCell::new(Vec::new());
        let result = quarantine_before_journal(
            || {
                events.borrow_mut().push("quarantine-failed");
                Err(QemuPersistentBootError::DeviceQuarantine)
            },
            || {
                events.borrow_mut().push("journal-first-read");
                Ok::<_, QemuPersistentBootError>(())
            },
        );

        assert_eq!(result, Err(QemuPersistentBootError::DeviceQuarantine));
        assert_eq!(events.into_inner(), ["quarantine-failed"]);
    }
}

/// The frozen, QEMU-only DMA arena contract shared by production and the
/// experiment profiles. It describes guest PFNs, emulated IOVAs, and backing
/// file offsets—not host physical identity.
pub(crate) fn persistent_dma_arena_digest(layout: PersistentDmaArenaLayout) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus-cser-persistent-dma-arena-v1");
    hasher.update(layout.version().to_le_bytes());
    hasher.update((layout.page_count() as u64).to_le_bytes());
    hasher.update((layout.paddr_base() as u64).to_le_bytes());
    hasher.update((layout.daddr_base() as u64).to_le_bytes());
    for kind in [
        OwnerKind::QueueDriver,
        OwnerKind::QueueDevice,
        OwnerKind::Request,
    ] {
        hasher.update((layout.paddr(kind) as u64).to_le_bytes());
        hasher.update((layout.daddr(kind) as u64).to_le_bytes());
        hasher.update((layout.qemu_backing_offset(kind) as u64).to_le_bytes());
    }
    Digest::new(hasher.finalize().into())
}
