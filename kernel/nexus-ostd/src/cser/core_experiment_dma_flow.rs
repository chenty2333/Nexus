// SPDX-License-Identifier: MPL-2.0

//! Shared real-VirtIO flow for the tool-plus-DMA experiment arms.
//!
//! This is deliberately a *linear owner facade*, rather than a second device
//! model.  It prepares and publishes a real VirtIO request, and carries the
//! exact published/completed/reset/IOTLB owners between the two experiment
//! arms.  Neither arm gets a `bool` standing for publication or quiescence.
//! CSER obtains its verifier-bound adapter inputs; the baseline obtains a
//! baseline-local raw observation from the same non-forgeable closure.

use cser_core::{CommitIntent, CoreError, Digest, Engine};
use nexus_ostd_virtio::{
    CompletedRequest, InterruptCompletionProgress, InterruptReceipt, PreparationEvidenceFailure,
    PrepareReadError, ProductionClosureProgress, ProductionClosureReceipt, ProductionDevice,
    ProductionIotlbBeginFailure, ProductionResetAck, ProductionResetRetryFailure,
    ProductionResetTombstone, PublishedRequest, ReceiptedPreparedRequest, Root,
};
use sha2::{Digest as _, Sha256};

use super::core_dma_adapter::{
    CoreDmaCohort, CoreIotlbEvidence, CoreIotlbEvidenceFailure, CorePublishedQueue,
    CoreQueueBindFailure, CoreQueueCommitFailure, CoreQueuePublishFailure, CoreResetEvidence,
    CoreResetEvidenceFailure, ExperimentDmaResource, apply_real_iotlb_closure,
    apply_real_reset_generation, bind_queue_commit, publish_real_queue,
};

/// A real request prepared in interrupt mode and bound to its preparation
/// receipt.  It is the sole input to either publication path.
#[must_use = "publish, cancel, or retain the real prepared request"]
pub(crate) struct LiveDmaPrepared(ReceiptedPreparedRequest);

/// Failure to prepare a request without discarding its production owner.
pub(crate) enum LiveDmaPrepareFailure {
    Prepare(PrepareReadError),
    Receipt(PreparationEvidenceFailure),
}

/// Prepares the actual QEMU VirtIO sector-zero request and obtains the
/// production receipt before either experiment records a commit intent.
pub(crate) fn prepare_live_irq(
    device: &mut ProductionDevice,
    root: &mut Root,
) -> Result<LiveDmaPrepared, LiveDmaPrepareFailure> {
    let prepared = device
        .prepare_read_sector0_irq(root)
        .map_err(LiveDmaPrepareFailure::Prepare)?;
    let receipted = device
        .issue_preparation_receipt(prepared)
        .map_err(LiveDmaPrepareFailure::Receipt)?;
    Ok(LiveDmaPrepared(receipted))
}

/// Prepares the same real sector-zero request through the polling completion
/// mode.  The experiment uses this only for the first boot's device-visible
/// publication; a subsequent crash recovery deliberately closes the retained
/// coordinate through boot quarantine rather than manufacturing an IRQ
/// receipt after process loss.
pub(crate) fn prepare_live_polling(
    device: &mut ProductionDevice,
    root: &mut Root,
) -> Result<LiveDmaPrepared, LiveDmaPrepareFailure> {
    let prepared = device
        .prepare_read_sector0(root)
        .map_err(LiveDmaPrepareFailure::Prepare)?;
    let receipted = device
        .issue_preparation_receipt(prepared)
        .map_err(LiveDmaPrepareFailure::Receipt)?;
    Ok(LiveDmaPrepared(receipted))
}

impl LiveDmaPrepared {
    /// The real preparation identity used to bind the component cohort before
    /// `avail.idx` is made visible.
    pub(crate) fn identity(&self) -> nexus_ostd_virtio::DeviceSessionIdentity {
        self.0.identity()
    }

    /// A stable, domain-separated operation digest for the CSER component
    /// intent.  It is derived from the opaque production receipt, not caller
    /// supplied coordinates.
    pub(crate) fn operation_digest(&self) -> Digest {
        let receipt = self.0.receipt();
        let identity = receipt.identity();
        let attempt = receipt.attempt();
        let mut hasher = Sha256::new();
        hasher.update(b"nexus.cser.experiment.virtio-preparation.v1");
        hasher.update(receipt.digest().to_le_bytes());
        hasher.update(attempt.owner_id().to_le_bytes());
        hasher.update(attempt.sequence().to_le_bytes());
        hasher.update(identity.device_generation().to_le_bytes());
        hasher.update(identity.queue().to_le_bytes());
        hasher.update(identity.descriptor_token().to_le_bytes());
        Digest::new(hasher.finalize().into())
    }

    /// Binds the exact durable CSER intent to the real device cohort and makes
    /// the actual `avail.idx` publication visible.  A failed bind/publication
    /// returns the complete linear authority through the adapter's failures.
    pub(crate) fn publish_cser(
        self,
        engine: &Engine,
        intent: CommitIntent,
        cohort: CoreDmaCohort,
        device: &ProductionDevice,
    ) -> Result<CserLiveDma, LiveCserPublishFailure> {
        let authority =
            bind_queue_commit(engine, intent, cohort).map_err(LiveCserPublishFailure::Bind)?;
        let published = publish_real_queue(device, self.0, authority)
            .map_err(LiveCserPublishFailure::Publish)?;
        Ok(CserLiveDma(published))
    }

    /// Baseline publication uses the very same production preflight/apply
    /// path, but intentionally creates no CSER command or verifier authority.
    pub(crate) fn publish_baseline(
        self,
        device: &ProductionDevice,
    ) -> Result<BaselineLiveDma, LiveBaselinePublishFailure> {
        let identity = self.0.identity();
        let intent = device
            .preflight_publish(self.0, identity)
            .map_err(LiveBaselinePublishFailure::Preflight)?;
        let mut request = intent.apply();
        let notification = request.notify();
        Ok(BaselineLiveDma {
            request,
            notification,
        })
    }
}

pub(crate) enum LiveCserPublishFailure {
    Bind(CoreQueueBindFailure),
    Publish(CoreQueuePublishFailure),
}

pub(crate) enum LiveBaselinePublishFailure {
    Preflight(nexus_ostd_virtio::PreparationPublishFailure),
}

/// A real published request plus CSER's typed commit verifier input.
#[must_use = "verify the CSER commit or retain the real published request"]
pub(crate) struct CserLiveDma(CorePublishedQueue);

impl CserLiveDma {
    /// Verifies publication against the exact durable intent.  The failure
    /// retains both the physical request and the unacknowledged intent.
    pub(crate) fn verify_commit(
        self,
        engine: &Engine,
    ) -> Result<CserCommittedLiveDma, CoreQueueCommitFailure> {
        let committed = self.0.verify_commit(engine)?;
        let (request, acknowledgement) = committed.into_parts();
        Ok(CserCommittedLiveDma {
            request,
            acknowledgement,
        })
    }
}

/// CSER commit acknowledgement and its still-live physical request.
#[must_use = "durably submit acknowledgement and close or retain DMA"]
pub(crate) struct CserCommittedLiveDma {
    request: PublishedRequest,
    acknowledgement: cser_core::Command,
}

impl CserCommittedLiveDma {
    pub(crate) fn into_parts(self) -> (BaselineLiveDma, cser_core::Command) {
        (
            BaselineLiveDma {
                request: self.request,
                notification: nexus_ostd_virtio::NotificationDisposition::Kicked,
            },
            self.acknowledgement,
        )
    }
}

/// A real device-visible request used by either arm after publication.
#[must_use = "complete/reset or retain the real published request"]
pub(crate) struct BaselineLiveDma {
    request: PublishedRequest,
    notification: nexus_ostd_virtio::NotificationDisposition,
}

impl BaselineLiveDma {
    pub(crate) const fn notification(&self) -> nexus_ostd_virtio::NotificationDisposition {
        self.notification
    }

    /// Completes only from the exact opaque ISR receipt produced by the real
    /// top-half acknowledgement.  Foreign or premature receipts retain the
    /// request in the returned production progress value.
    pub(crate) fn complete_after_irq(self, irq: InterruptReceipt) -> InterruptCompletionProgress {
        self.request.complete_after_interrupt(irq)
    }

    /// Transfers the exact published owner to the real IRQ actor.  The actor
    /// is the only code allowed to obtain the matching ISR receipt before
    /// task-context completion and reset.
    pub(crate) fn into_published_request(self) -> PublishedRequest {
        self.request
    }

    /// Starts a reset for a published-but-not-completed request.  The complete
    /// owner is carried by `ProductionResetTombstone`.
    pub(crate) fn begin_reset(self, pending_once: bool) -> ProductionResetTombstone {
        self.request.begin_reset(pending_once)
    }
}

/// Begins reset from a completed real request.  This does not synthesize a
/// completion or drain fact; callers must retain the matching IRQ receipt.
pub(crate) fn begin_completed_reset(
    completed: CompletedRequest,
    pending_once: bool,
) -> ProductionResetTombstone {
    completed.begin_reset(pending_once)
}

/// One successful reset observation, still owning the exact closure authority.
#[must_use = "apply generation and IOTLB closure or retain reset authority"]
pub(crate) struct LiveResetAck {
    reset: ProductionResetAck,
    irq: InterruptReceipt,
}

/// Retries are explicit: a pending reset returns the complete tombstone rather
/// than an untyped retry flag.
pub(crate) fn probe_reset_once(
    tombstone: ProductionResetTombstone,
    root: &mut Root,
    irq: InterruptReceipt,
) -> Result<LiveResetAck, ProductionResetRetryFailure> {
    tombstone
        .probe_ack_once(root)
        .map(|reset| LiveResetAck { reset, irq })
}

impl LiveResetAck {
    /// Supplies CSER's reset/IRQ typed verifier inputs.  The adapter checks
    /// identity, retained-page count, generation plan, and IRQ attempt.
    pub(crate) fn bind_cser(
        self,
        device: &mut ProductionDevice,
        cohort: CoreDmaCohort,
    ) -> Result<CserResetLiveDma, CoreResetEvidenceFailure> {
        let reset = apply_real_reset_generation(device, self.reset, cohort)?;
        Ok(CserResetLiveDma {
            reset,
            irq: self.irq,
            cohort,
        })
    }

    /// Applies generation and starts IOTLB closure for the baseline without
    /// importing CSER evidence.  The returned closure remains opaque and is
    /// the only source of the baseline's raw quiescence receipt.
    pub(crate) fn begin_baseline_iotlb(
        mut self,
        device: &mut ProductionDevice,
        pending_once: bool,
    ) -> Result<BaselineClosureProgress, LiveBaselineCloseError> {
        let plan = device
            .prepare_generation_advance(&mut self.reset)
            .map_err(LiveBaselineCloseError::Generation)?;
        let successor_generation = plan.apply();
        let closure = device
            .begin_iotlb(self.reset, pending_once)
            .map_err(LiveBaselineCloseError::Iotlb)?;
        Ok(BaselineClosureProgress {
            closure,
            irq: self.irq,
            successor_generation,
        })
    }
}

pub(crate) struct CserResetLiveDma {
    reset: CoreResetEvidence,
    irq: InterruptReceipt,
    cohort: CoreDmaCohort,
}

impl CserResetLiveDma {
    pub(crate) fn reset_commands(
        &self,
        engine: &Engine,
    ) -> Result<[cser_core::Command; 3], CoreError> {
        Ok([
            self.reset.reset_command(
                engine,
                self.cohort,
                super::core_dma_adapter::ClaimRole::Queue,
            )?,
            self.reset.reset_command(
                engine,
                self.cohort,
                super::core_dma_adapter::ClaimRole::PinnedPages,
            )?,
            self.reset.reset_command(
                engine,
                self.cohort,
                super::core_dma_adapter::ClaimRole::Iova,
            )?,
        ])
    }

    pub(crate) fn irq_drain_command(
        &self,
        engine: &Engine,
    ) -> Result<cser_core::Command, CoreError> {
        self.reset
            .irq_drained_command(engine, self.cohort, self.irq)
    }

    pub(crate) fn begin_iotlb(
        self,
        engine: &Engine,
        device: &ProductionDevice,
        pending_once: bool,
    ) -> Result<ProductionClosureProgress, super::core_dma_adapter::CoreIotlbBeginFailure> {
        self.reset
            .begin_iotlb(engine, device, self.cohort, pending_once)
    }

    pub(crate) fn bind_iotlb(
        device: &mut ProductionDevice,
        closure: ProductionClosureReceipt,
        cohort: CoreDmaCohort,
    ) -> Result<CoreIotlbEvidence, CoreIotlbEvidenceFailure> {
        apply_real_iotlb_closure(device, closure, cohort)
    }
}

pub(crate) enum LiveBaselineCloseError {
    Generation(nexus_ostd_virtio::ResetGenerationError),
    Iotlb(ProductionIotlbBeginFailure),
}

/// A real IOTLB closure plus the exact ISR receipt that preceded it.
#[must_use = "apply closure and mint baseline raw evidence, or retain it"]
pub(crate) struct BaselineClosureProgress {
    closure: ProductionClosureProgress,
    irq: InterruptReceipt,
    successor_generation: u64,
}

impl BaselineClosureProgress {
    pub(crate) fn into_parts(self) -> (ProductionClosureProgress, InterruptReceipt, u64) {
        (self.closure, self.irq, self.successor_generation)
    }
}

/// Baseline-local, non-forgeable raw quiescence observation.  It exposes no
/// arbitrary success booleans: it can only be created after applying a real
/// three-page IOTLB closure with the retained IRQ receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BaselineRawDmaEvidence {
    resource: ExperimentDmaResource,
    successor_generation: u64,
    irq: InterruptReceipt,
    completed_pages: usize,
}

impl BaselineRawDmaEvidence {
    pub(crate) const fn resource(self) -> ExperimentDmaResource {
        self.resource
    }
    pub(crate) const fn successor_generation(self) -> u64 {
        self.successor_generation
    }
    pub(crate) const fn completed_pages(self) -> usize {
        self.completed_pages
    }
    pub(crate) const fn irq(self) -> InterruptReceipt {
        self.irq
    }
}

/// Applies exactly one completed baseline IOTLB receipt and yields the raw
/// baseline evidence.  The identity and generation are rechecked by the
/// production facade before its infallible apply.
pub(crate) fn apply_baseline_iotlb(
    device: &mut ProductionDevice,
    mut closure: ProductionClosureReceipt,
    irq: InterruptReceipt,
    resource: ExperimentDmaResource,
    successor_generation: u64,
) -> Result<BaselineRawDmaEvidence, nexus_ostd_virtio::QuiescenceApplyError> {
    if closure.completed_pages() != 3 {
        return Err(nexus_ostd_virtio::QuiescenceApplyError::WrongCompletedPages);
    }
    let plan = device.prepare_quiescence_apply(&mut closure)?;
    let identity = plan.apply();
    if identity.device_generation() >= successor_generation {
        return Err(nexus_ostd_virtio::QuiescenceApplyError::WrongGeneration);
    }
    Ok(BaselineRawDmaEvidence {
        resource,
        successor_generation,
        irq,
        completed_pages: closure.completed_pages(),
    })
}
