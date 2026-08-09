// SPDX-License-Identifier: MPL-2.0

//! Strong independent-finalizer experiment arm.
//!
//! This orchestration layer intentionally owns no CSER state or authority.
//! It drives [`super::core_baseline_runtime`] through the same seven durable
//! crash barriers as the CSER arm.  Concrete production wiring supplies a
//! `BaselineEndpointProvider` implemented over the COM2 HTTP bridge and a
//! `BaselineDmaProvider` implemented over the real VirtIO reset/IRQ/IOTLB
//! owners.  The latter is deliberately a trait boundary: it prevents this
//! comparison arm from fabricating a device observation while the shared
//! hardware primitives remain owned by the production device module.

use sha2::{Digest as _, Sha256};

use super::core_tool_uart::{
    OperationKey, ToolRequest, ToolRunId, ToolTerminalRecord, ToolUart, ToolV2Identity,
};
use super::{
    core_baseline_runtime::{
        BASELINE_RECORD_BYTES, BaselineDigest, BaselineDmaReceipt, BaselineDmaReceiptVerifier,
        BaselineDoubleBank, BaselineDurableStore, BaselineError, BaselineExperimentEvent,
        BaselineExperimentSink, BaselineFinalizer, BaselineOperationKey, BaselineRecord,
        BaselineReuseGate, BaselineRuntime, BaselineToolReceipt, BaselineToolReceiptVerifier,
        DmaFinalizer, ToolFinalizer, ToolOutcome, decode_baseline_record, encode_baseline_record,
    },
    core_dma_adapter::{
        ExperimentDmaQuiescence, ExperimentDmaQuiescenceError, ExperimentDmaResource,
        run_experiment_quiescence,
    },
    core_pio_journal::{AtaDoubleBank, AtaDoubleBankError, AtaJournalFixture, AtaPioError},
    core_tpm_anchor::{
        ExperimentAnchorSnapshot, ExperimentNvAnchor, ExperimentNvAnchorError, ExperimentNvLayout,
        QemuTisTpm2, TisTpmError, TpmNvIndexAuth,
    },
};

/// The closed crash matrix shared by the CSER and reconstructed-baseline arms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum BaselineCutpoint {
    TopologyDurable = 1,
    IntentsDurable = 2,
    EndpointPostApplied = 3,
    DmaPublished = 4,
    ToolOutcomeDurable = 5,
    ReconciliationIntentDurable = 6,
    RetirementsAndGateDurable = 7,
}

impl BaselineCutpoint {
    pub(crate) const fn id(self) -> u16 {
        self as u16
    }
}

/// Host-directed durable crash barrier.  Implementations must emit a barrier
/// only after the named predecessor state transition is durable.
pub(crate) trait BaselineCrashHook {
    type Error;

    fn reached(&mut self, cutpoint: BaselineCutpoint) -> Result<(), Self::Error>;
}

/// Independently verified tool finalizer source.
///
/// The concrete provider POSTs/GETs the same UART/HTTP endpoint as CSER.  It
/// may return a tool finalizer only after its latest terminal-record verifier
/// checked operation identity, payload digest, and endpoint record digest.
pub(crate) trait BaselineEndpointProvider {
    type Error;

    /// Issues the immutable POST, or performs the recovery GET/retry for that
    /// same operation.  It must not itself make an old-epoch finalizer.
    fn dispatch_or_recover_tool(&mut self) -> Result<(), Self::Error>;

    /// Re-reads and verifies the terminal endpoint record after the executor
    /// fence has advanced.  This is deliberately separate from dispatch:
    /// finalizer authority is bound to the current fenced epoch, whereas the
    /// endpoint operation was allowed to start under its predecessor.
    fn verified_tool_finalizer(&mut self, epoch: u64) -> Result<BaselineFinalizer, Self::Error>;
}

/// Independently verified DMA quiescence finalizer source.
///
/// A provider must drive the real VirtIO reset, observe the exact IRQ drain,
/// and complete the real IOTLB invalidation before returning.  Its returned
/// finalizer is required to bind the registered resource and generation.
pub(crate) trait BaselineDmaProvider {
    type Error;

    /// Makes the DMA action device-visible. This returns only after actual
    /// VirtIO publication, so cutpoint four has the same meaning in both arms.
    fn publish_dma_visible(&mut self) -> Result<(), Self::Error>;

    /// Returns independently verified reset/IRQ/IOTLB quiescence after the
    /// durable executor fence, bound into the returned finalizer.
    fn verified_dma_finalizer(&mut self, epoch: u64) -> Result<BaselineFinalizer, Self::Error>;
}

/// Errors at orchestration boundaries.  Endpoint, DMA, and barrier failures
/// retain the durable baseline record; none is translated into a release.
#[derive(Debug)]
pub(crate) enum BaselineExperimentError<E, D, H> {
    Baseline(BaselineError),
    Endpoint(E),
    Dma(D),
    Barrier(H),
    WrongFinalizer,
}

/// Common comparison metrics.  Field names mirror the host matrix JSONL
/// schema; the host, rather than this no-std guest module, serializes them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BaselineMetrics {
    pub(crate) retired_by_evidence: u64,
    pub(crate) retained_claims: u64,
    pub(crate) gate_rejections: u64,
    pub(crate) reconciliation_steps: u64,
    pub(crate) topology_registered: bool,
    pub(crate) tool_finalized: bool,
    pub(crate) dma_finalized: bool,
    pub(crate) reuse_authorized: bool,
}

impl BaselineMetrics {
    /// Reconstructs durable trial totals on a recovery boot. `gate_rejections`
    /// intentionally remains zero: the fixed baseline record has no
    /// historical rejection counter, so reporting a synthetic total would
    /// make the comparison less honest.
    fn from_durable_record(record: BaselineRecord) -> Self {
        Self {
            retired_by_evidence: u64::from(record.tool_finalized())
                + u64::from(record.dma_finalized()),
            retained_claims: u64::from(record.tool_dispatched() && !record.tool_finalized())
                + u64::from(record.dma_dispatched() && !record.dma_finalized()),
            gate_rejections: 0,
            reconciliation_steps: u64::from(record.reconciliation_intent_recorded()),
            topology_registered: record.topology_registered(),
            tool_finalized: record.tool_finalized(),
            dma_finalized: record.dma_finalized(),
            reuse_authorized: record.reuse_authorized(),
        }
    }

    pub(crate) fn invariants_hold(self) -> bool {
        (!self.reuse_authorized || (self.tool_finalized && self.dma_finalized))
            && (!self.tool_finalized || self.topology_registered)
            && (!self.dma_finalized || self.topology_registered)
    }
}

impl BaselineExperimentSink for BaselineMetrics {
    fn record(&mut self, event: BaselineExperimentEvent) {
        match event {
            BaselineExperimentEvent::TopologyRegistered { .. } => self.topology_registered = true,
            BaselineExperimentEvent::ToolFinalized { .. } => {
                assert!(
                    self.retained_claims > 0,
                    "a tool finalizer cannot retire an unretained claim"
                );
                self.retained_claims -= 1;
                self.tool_finalized = true;
                self.retired_by_evidence = self.retired_by_evidence.saturating_add(1);
            }
            BaselineExperimentEvent::DmaFinalized { .. } => {
                assert!(
                    self.retained_claims > 0,
                    "a DMA finalizer cannot retire an unretained claim"
                );
                self.retained_claims -= 1;
                self.dma_finalized = true;
                self.retired_by_evidence = self.retired_by_evidence.saturating_add(1);
            }
            BaselineExperimentEvent::ReuseWithheld { .. } => {
                self.gate_rejections = self.gate_rejections.saturating_add(1);
            }
            BaselineExperimentEvent::ReuseAuthorized { .. } => self.reuse_authorized = true,
            BaselineExperimentEvent::ReconciliationIntentRecorded { .. } => {
                self.reconciliation_steps = self.reconciliation_steps.saturating_add(1);
            }
            BaselineExperimentEvent::ToolDispatched { .. }
            | BaselineExperimentEvent::DmaDispatched { .. } => {
                self.retained_claims = self.retained_claims.saturating_add(1);
            }
            BaselineExperimentEvent::ExecutorFenced { .. } => {}
        }
    }
}

/// One durable baseline trial.  The caller creates `record` only after the
/// shared ATA/TPM-backed topology registration is durable; an integration
/// adapter replaces the in-memory `BaselineRuntime` cell with that backing
/// implementation before this arm is considered production evidence.
pub(crate) struct BaselineExperimentArm<D = BaselineDoubleBank> {
    runtime: BaselineRuntime<D, BaselineMetrics>,
}

impl BaselineExperimentArm<BaselineDoubleBank> {
    pub(crate) fn new(record: BaselineRecord) -> Self {
        Self {
            runtime: BaselineRuntime::new(record, BaselineMetrics::default()),
        }
    }
}

impl<D: BaselineDurableStore> BaselineExperimentArm<D> {
    /// Registers through the supplied independent durable store.  The store
    /// owns only baseline bytes and an experiment TPM tip; it has no CSER
    /// catalog, engine, claim, or permit authority.
    pub(crate) fn initialize_durable(
        durable: D,
        record: BaselineRecord,
    ) -> Result<Self, BaselineError> {
        Ok(Self {
            runtime: BaselineRuntime::initialize_durable(
                durable,
                record,
                BaselineMetrics::default(),
            )?,
        })
    }

    pub(crate) fn recover(durable: D) -> Result<Self, BaselineError> {
        let mut durable = durable;
        let metrics = BaselineMetrics::from_durable_record(durable.recover()?);
        Ok(Self {
            runtime: BaselineRuntime::from_durable(durable, metrics)?,
        })
    }

    pub(crate) fn metrics(&self) -> &BaselineMetrics {
        self.runtime.sink()
    }

    pub(crate) fn record(&mut self) -> Result<BaselineRecord, BaselineError> {
        self.runtime.snapshot()
    }

    /// Runs the entire seven-cutpoint arm.  A host that kills QEMU at any hook
    /// restarts from the independent ATA/TPM baseline record.
    pub(crate) fn execute<E, P, H>(
        &mut self,
        endpoint: &mut E,
        dma: &mut P,
        hook: &mut H,
    ) -> Result<BaselineReuseGate, BaselineExperimentError<E::Error, P::Error, H::Error>>
    where
        E: BaselineEndpointProvider,
        P: BaselineDmaProvider,
        H: BaselineCrashHook,
    {
        self.execute_resume(endpoint, dma, hook)
    }

    /// Continues the fixed workload from its *durable* baseline record.
    ///
    /// A QEMU kill loses the caller's endpoint and device owners, but must not
    /// make it legal to redispatch either escaped action.  The next boot reads
    /// the independent ATA/TPM record before every phase and invokes a
    /// provider only for a fact which has not yet become durable.  In
    /// particular, a crash after POST uses the provider's recovery GET path,
    /// while a crash after DMA publication asks its recovered/quarantined
    /// provider only for quiescence evidence.
    pub(crate) fn execute_resume<E, P, H>(
        &mut self,
        endpoint: &mut E,
        dma: &mut P,
        hook: &mut H,
    ) -> Result<BaselineReuseGate, BaselineExperimentError<E::Error, P::Error, H::Error>>
    where
        E: BaselineEndpointProvider,
        P: BaselineDmaProvider,
        H: BaselineCrashHook,
    {
        let mut record = self
            .runtime
            .snapshot()
            .map_err(BaselineExperimentError::Baseline)?;
        if !record.topology_registered() {
            return Err(BaselineExperimentError::Baseline(
                BaselineError::NotRegistered,
            ));
        }
        if !record.tool_dispatched() && !record.dma_dispatched() {
            // The arm is constructed only after this complete topology has
            // reached the independent durable store.
            self.runtime
                .dispatch_tool_and_dma()
                .map_err(BaselineExperimentError::Baseline)?;
            // The seven-cut matrix begins only after device-visible DMA
            // publication has the baseline's durable acknowledgement. The
            // tiny publish-to-ack interval is deliberately outside this
            // matrix and is not claimed recoverable by this baseline.
            dma.publish_dma_visible()
                .map_err(BaselineExperimentError::Dma)?;
            self.runtime
                .record_dma_published()
                .map_err(BaselineExperimentError::Baseline)?;
            self.hit(hook, BaselineCutpoint::TopologyDurable)?;
            self.hit(hook, BaselineCutpoint::IntentsDurable)?;
            record = self
                .runtime
                .snapshot()
                .map_err(BaselineExperimentError::Baseline)?;
        } else if !record.tool_dispatched() || !record.dma_dispatched() {
            // This is unreachable for records produced by
            // `dispatch_tool_and_dma`; do not invent the missing half.
            return Err(BaselineExperimentError::Baseline(
                BaselineError::RecordCorrupt,
            ));
        }

        if !record.endpoint_applied() {
            endpoint
                .dispatch_or_recover_tool()
                .map_err(BaselineExperimentError::Endpoint)?;
            self.runtime
                .record_endpoint_applied()
                .map_err(BaselineExperimentError::Baseline)?;
            self.hit(hook, BaselineCutpoint::EndpointPostApplied)?;
            // Both escaped effects are durable observations here: the tool
            // endpoint row and the earlier DMA-publication acknowledgement.
            self.hit(hook, BaselineCutpoint::DmaPublished)?;
            record = self
                .runtime
                .snapshot()
                .map_err(BaselineExperimentError::Baseline)?;
        }

        if !record.dma_published() {
            dma.publish_dma_visible()
                .map_err(BaselineExperimentError::Dma)?;
            self.runtime
                .record_dma_published()
                .map_err(BaselineExperimentError::Baseline)?;
            record = self
                .runtime
                .snapshot()
                .map_err(BaselineExperimentError::Baseline)?;
        }

        let epoch = self
            .runtime
            .fence_executor()
            .map_err(BaselineExperimentError::Baseline)?;
        if !record.tool_finalized() {
            let tool = endpoint
                .verified_tool_finalizer(epoch)
                .map_err(BaselineExperimentError::Endpoint)?;
            if !matches!(tool, BaselineFinalizer::Tool(_)) {
                return Err(BaselineExperimentError::WrongFinalizer);
            }
            self.runtime
                .finalize(tool)
                .map_err(BaselineExperimentError::Baseline)?;
            self.hit(hook, BaselineCutpoint::ToolOutcomeDurable)?;
            record = self
                .runtime
                .snapshot()
                .map_err(BaselineExperimentError::Baseline)?;
        }

        if !record.reconciliation_intent_recorded() {
            self.runtime
                .record_reconciliation_intent()
                .map_err(BaselineExperimentError::Baseline)?;
            self.hit(hook, BaselineCutpoint::ReconciliationIntentDurable)?;
            record = self
                .runtime
                .snapshot()
                .map_err(BaselineExperimentError::Baseline)?;
        }

        if !record.dma_finalized() {
            let quiescence = dma
                .verified_dma_finalizer(epoch)
                .map_err(BaselineExperimentError::Dma)?;
            if !matches!(quiescence, BaselineFinalizer::Dma(_)) {
                return Err(BaselineExperimentError::WrongFinalizer);
            }
            self.runtime
                .finalize(quiescence)
                .map_err(BaselineExperimentError::Baseline)?;
            record = self
                .runtime
                .snapshot()
                .map_err(BaselineExperimentError::Baseline)?;
        }

        let (gate, newly_authorized) = if let Some(gate) = self
            .runtime
            .recovered_reuse_gate()
            .map_err(BaselineExperimentError::Baseline)?
        {
            (gate, false)
        } else if record.reusable() {
            (
                self.runtime
                    .reserve_reuse()
                    .map_err(BaselineExperimentError::Baseline)?,
                true,
            )
        } else {
            return Err(BaselineExperimentError::Baseline(BaselineError::NotClosed));
        };
        if newly_authorized {
            self.hit(hook, BaselineCutpoint::RetirementsAndGateDurable)?;
        }
        debug_assert!(self.metrics().invariants_hold());
        Ok(gate)
    }

    fn hit<E, P, H>(
        &mut self,
        hook: &mut H,
        cutpoint: BaselineCutpoint,
    ) -> Result<(), BaselineExperimentError<E, P, H::Error>>
    where
        H: BaselineCrashHook,
    {
        hook.reached(cutpoint)
            .map_err(BaselineExperimentError::Barrier)
    }
}

/// Independent ATA/TPM durable store for the reconstructed baseline.  Its
/// ordering is ATA publish/readback first, then the experiment-only TPM tip.
/// A recovery may finish exactly that one interrupted anchor advance, but
/// only after decoding the complete ATA record and only when it is precisely
/// one revision ahead of the TPM. Any other mismatch is never interpreted as
/// permission to reuse.
pub(crate) struct AtaTpmBaselineStore {
    ata: AtaDoubleBank,
    anchor: ExperimentNvAnchor<QemuTisTpm2>,
}

impl AtaTpmBaselineStore {
    pub(crate) fn acquire_qemu_fixture(
        fixture: AtaJournalFixture,
    ) -> Result<Self, AtaTpmBaselineStoreError> {
        let mut ata = AtaDoubleBank::acquire(fixture).map_err(AtaTpmBaselineStoreError::Ata)?;
        let transport =
            QemuTisTpm2::acquire_qemu_fixture().map_err(AtaTpmBaselineStoreError::Tpm)?;
        let auth = TpmNvIndexAuth::new(&[]).map_err(AtaTpmBaselineStoreError::Auth)?;
        let layout = ExperimentNvLayout::qemu_fixture();
        let initial = ExperimentAnchorSnapshot::new(0, [0; 32]);
        let record = ata.load().map_err(AtaTpmBaselineStoreError::Ata)?;
        let anchor = ExperimentNvAnchor::open(transport, layout, auth)
            .map_err(AtaTpmBaselineStoreError::Anchor)?;
        if record.is_none() && anchor.snapshot() != initial {
            return Err(AtaTpmBaselineStoreError::UnexpectedGenesis);
        }
        Ok(Self { ata, anchor })
    }

    /// Checks whether the independent baseline medium contains a complete
    /// selected record.  This is used only to choose initialization versus
    /// recovery; validation and TPM-tip binding still happen in `recover`.
    pub(crate) fn has_record(&mut self) -> Result<bool, AtaTpmBaselineStoreError> {
        self.ata
            .load()
            .map(|record| record.is_some())
            .map_err(AtaTpmBaselineStoreError::Ata)
    }

    /// Selects a monotonic device generation from the independent experiment
    /// tip before the common VirtIO quarantine begins.  This is intentionally
    /// not the CSER TPM layout: the baseline cannot parse or depend on a
    /// Registry anchor merely to choose a physical fence generation.
    pub(crate) fn next_device_generation(&self) -> Result<u64, AtaTpmBaselineStoreError> {
        self.anchor
            .snapshot()
            .revision()
            .checked_add(1)
            .ok_or(AtaTpmBaselineStoreError::GenerationExhausted)
    }
}

#[derive(Debug)]
pub(crate) enum AtaTpmBaselineStoreError {
    Ata(AtaDoubleBankError<AtaPioError>),
    Tpm(TisTpmError),
    Auth(super::core_tpm_anchor::TpmNvAuthError),
    Anchor(ExperimentNvAnchorError<TisTpmError>),
    UnexpectedGenesis,
    GenerationExhausted,
}

impl BaselineDurableStore for AtaTpmBaselineStore {
    fn recover(&mut self) -> Result<BaselineRecord, BaselineError> {
        let tip = self.anchor.snapshot();
        let snapshot = self
            .ata
            .load()
            .map_err(|_| BaselineError::RecordCorrupt)?
            .ok_or(BaselineError::RecordCorrupt)?;
        if snapshot.bytes().len() != BASELINE_RECORD_BYTES {
            return Err(BaselineError::RecordCorrupt);
        }
        let mut bytes = [0; BASELINE_RECORD_BYTES];
        bytes.copy_from_slice(snapshot.bytes());
        match snapshot.revision() {
            revision if revision == tip.revision() && snapshot.digest() == tip.digest() => {
                decode_baseline_record(&bytes, revision)
            }
            revision
                if revision
                    == tip
                        .revision()
                        .checked_add(1)
                        .ok_or(BaselineError::RecordCorrupt)? =>
            {
                // ATA write/readback completed, but a crash interrupted the
                // independent TPM selector advance.  The complete next
                // record is the only safe roll-forward candidate: decode it
                // before advancing the anchor, then make that exact digest
                // authoritative.  Any other skew remains fail-closed.
                decode_baseline_record(&bytes, revision)?;
                let replacement = ExperimentAnchorSnapshot::new(revision, snapshot.digest());
                self.anchor
                    .compare_and_advance(tip, replacement)
                    .map_err(|_| BaselineError::RecordCorrupt)?;
                if self.anchor.snapshot() != replacement {
                    return Err(BaselineError::RecordCorrupt);
                }
                decode_baseline_record(&bytes, revision)
            }
            _ => Err(BaselineError::RecordCorrupt),
        }
    }

    fn persist(&mut self, record: BaselineRecord) -> Result<(), BaselineError> {
        let previous = self.anchor.snapshot();
        let revision = previous
            .revision()
            .checked_add(1)
            .ok_or(BaselineError::RecordCorrupt)?;
        let bytes = encode_baseline_record(record, revision);
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        self.ata
            .publish(revision, digest, &bytes)
            .map_err(|_| BaselineError::RecordCorrupt)?;
        self.anchor
            .compare_and_advance(previous, ExperimentAnchorSnapshot::new(revision, digest))
            .map_err(|_| BaselineError::RecordCorrupt)
    }
}

/// DMA provider which translates the shared, non-forgeable quarantine receipt
/// into baseline-local finalizer authority.  It never imports a CSER receipt
/// or verifier and checks every raw resource coordinate again.
pub(crate) struct QuarantinedBaselineDma {
    record: BaselineRecord,
    proof: ExperimentDmaQuiescence,
}

impl QuarantinedBaselineDma {
    /// Captures the only accepted hardware input directly from the live
    /// `BootQuarantineGuard`.  This invokes the shared narrow interface that
    /// validates reset, two empty ISR reads, and remapped-IOTLB completion;
    /// callers cannot fill in booleans for those observations.
    pub(crate) fn from_quarantine(
        record: BaselineRecord,
        guard: &nexus_ostd_virtio::BootQuarantineGuard,
    ) -> Result<Self, QuarantinedBaselineDmaBuildError> {
        let resource = ExperimentDmaResource::new(record.resource().get(), record.generation())
            .ok_or(QuarantinedBaselineDmaBuildError::InvalidCoordinate)?;
        let proof = run_experiment_quiescence(guard, resource)
            .map_err(QuarantinedBaselineDmaBuildError::Quiescence)?;
        Ok(Self::new(record, proof))
    }

    pub(crate) fn new(record: BaselineRecord, proof: ExperimentDmaQuiescence) -> Self {
        Self { record, proof }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuarantinedBaselineDmaBuildError {
    InvalidCoordinate,
    Quiescence(ExperimentDmaQuiescenceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuarantinedBaselineDmaError {
    CoordinateMismatch,
    ReceiptRejected,
}

impl QuarantinedBaselineDma {
    /// Verifies a real, retained quarantine receipt. A runtime-specific DMA
    /// publisher composes this with `BaselineDmaProvider::publish_dma_visible`;
    /// this value intentionally cannot claim that it published a request.
    pub(crate) fn verified_finalizer(
        &self,
        epoch: u64,
    ) -> Result<BaselineFinalizer, QuarantinedBaselineDmaError> {
        let resource = self.proof.resource();
        if resource.resource() != self.record.resource().get()
            || resource.generation() != self.record.generation()
        {
            return Err(QuarantinedBaselineDmaError::CoordinateMismatch);
        }
        let receipt = BaselineDmaReceipt::observed(
            self.record.effect(),
            epoch,
            self.record.resource(),
            self.record.generation(),
            true,
            self.proof.isr_reads() >= 2,
            self.proof.completed_iotlb_pages() > 0,
        );
        let verifier = QuarantineReceiptVerifier {
            record: self.record,
            proof: self.proof,
        };
        DmaFinalizer::from_receipt(&verifier, receipt)
            .map(BaselineFinalizer::Dma)
            .map_err(|_| QuarantinedBaselineDmaError::ReceiptRejected)
    }
}

struct QuarantineReceiptVerifier {
    record: BaselineRecord,
    proof: ExperimentDmaQuiescence,
}

impl BaselineDmaReceiptVerifier for QuarantineReceiptVerifier {
    fn verify_dma_receipt(&self, receipt: &BaselineDmaReceipt) -> Result<(), BaselineError> {
        let resource = self.proof.resource();
        if resource.resource() != self.record.resource().get()
            || resource.generation() != self.record.generation()
            || self.proof.successor_generation() <= resource.generation()
            || self.proof.isr_reads() < 2
            || self.proof.completed_iotlb_pages() == 0
            || receipt.resource() != self.record.resource()
            || receipt.generation() != self.record.generation()
            || receipt.epoch() == 0
        {
            return Err(BaselineError::ReceiptRejected);
        }
        Ok(())
    }
}

/// Concrete independent verifier for the latest decoded UART terminal row.
/// It shares only the endpoint protocol with CSER; it does not convert a CSER
/// observation or obtain any core verification authority.
pub(crate) struct UartBaselineEndpoint<'a> {
    uart: &'a mut ToolUart,
    run: ToolRunId,
    operation: OperationKey,
    payload: &'a [u8],
    record: BaselineRecord,
    terminal: Option<ToolTerminalRecord>,
    identity: ToolV2Identity,
}

impl<'a> UartBaselineEndpoint<'a> {
    pub(crate) fn new_v2(
        uart: &'a mut ToolUart,
        identity: ToolV2Identity,
        run: ToolRunId,
        operation: OperationKey,
        payload: &'a [u8],
        record: BaselineRecord,
    ) -> Self {
        Self {
            uart,
            run,
            operation,
            payload,
            record,
            terminal: None,
            identity,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UartBaselineEndpointError {
    Transport(super::core_tool_uart::ToolUartError),
    Protocol(super::core_tool_uart::ToolProtocolError),
    MissingTerminal,
    BindingMismatch,
    ReceiptRejected,
}

impl BaselineEndpointProvider for UartBaselineEndpoint<'_> {
    type Error = UartBaselineEndpointError;

    fn dispatch_or_recover_tool(&mut self) -> Result<(), Self::Error> {
        let reply = self
            .uart
            .transact(
                &ToolRequest::new_v2(self.identity, self.run, self.operation, self.payload)
                    .map_err(UartBaselineEndpointError::Protocol)?,
            )
            .map_err(UartBaselineEndpointError::Transport)?;
        self.terminal = reply.terminal_record();
        if self.terminal.is_none() {
            return Err(UartBaselineEndpointError::MissingTerminal);
        }
        Ok(())
    }

    fn verified_tool_finalizer(&mut self, epoch: u64) -> Result<BaselineFinalizer, Self::Error> {
        // A crash after the POST marker is durable loses this boot's UART
        // response, not the endpoint operation identity. Re-read the exact
        // terminal row before deriving any finalizer; executor exit or the
        // local `endpoint_applied` bit is never outcome evidence.
        if self.terminal.is_none() {
            let digest = self.record.tool_binding().payload_digest().bytes();
            let reply = self
                .uart
                .transact(&ToolRequest::get_v2(
                    self.identity,
                    self.run,
                    self.operation,
                    digest,
                ))
                .map_err(UartBaselineEndpointError::Transport)?;
            self.terminal = reply.terminal_record();
        }
        let terminal = self
            .terminal
            .ok_or(UartBaselineEndpointError::MissingTerminal)?;
        let binding = self.record.tool_binding();
        if terminal.run_id() != self.run
            || terminal.outcome() != super::core_tool_uart::ToolTerminalOutcome::Success
            || BaselineOperationKey::from_operation_bytes(terminal.operation())
                != Some(binding.operation_key())
            || terminal.payload_digest() != binding.payload_digest().bytes()
        {
            return Err(UartBaselineEndpointError::BindingMismatch);
        }
        let receipt = BaselineToolReceipt::observed(
            self.record.effect(),
            epoch,
            binding.operation_key(),
            binding.payload_digest(),
            BaselineDigest::new(terminal.record_digest()),
            ToolOutcome::Succeeded,
        );
        let verifier = UartTerminalVerifier {
            record: self.record,
            run: self.run,
            terminal,
        };
        ToolFinalizer::from_receipt(&verifier, receipt)
            .map(BaselineFinalizer::Tool)
            .map_err(|_| UartBaselineEndpointError::ReceiptRejected)
    }
}

struct UartTerminalVerifier {
    record: BaselineRecord,
    run: ToolRunId,
    terminal: ToolTerminalRecord,
}

impl BaselineToolReceiptVerifier for UartTerminalVerifier {
    fn verify_tool_receipt(&self, receipt: &BaselineToolReceipt) -> Result<(), BaselineError> {
        let binding = self.record.tool_binding();
        if self.terminal.run_id() != self.run
            || self.terminal.outcome() != super::core_tool_uart::ToolTerminalOutcome::Success
            || BaselineOperationKey::from_operation_bytes(self.terminal.operation())
                != Some(binding.operation_key())
            || self.terminal.payload_digest() != binding.payload_digest().bytes()
            || self.terminal.record_digest() == [0; 32]
            || receipt
                != &BaselineToolReceipt::observed(
                    self.record.effect(),
                    receipt.epoch(),
                    binding.operation_key(),
                    binding.payload_digest(),
                    BaselineDigest::new(self.terminal.record_digest()),
                    ToolOutcome::Succeeded,
                )
        {
            return Err(BaselineError::ReceiptRejected);
        }
        Ok(())
    }
}

#[cfg(ktest)]
mod tests {
    use alloc::{sync::Arc, vec::Vec};
    use ostd::sync::SpinLock;

    use super::*;

    #[derive(Default)]
    struct OrderState {
        dma_published: bool,
        endpoint_applied: bool,
        barriers: Vec<u16>,
    }

    struct AcceptTool;

    impl BaselineToolReceiptVerifier for AcceptTool {
        fn verify_tool_receipt(&self, _: &BaselineToolReceipt) -> Result<(), BaselineError> {
            Ok(())
        }
    }

    struct AcceptDma;

    impl BaselineDmaReceiptVerifier for AcceptDma {
        fn verify_dma_receipt(&self, _: &BaselineDmaReceipt) -> Result<(), BaselineError> {
            Ok(())
        }
    }

    struct OrderedEndpoint {
        record: BaselineRecord,
        state: Arc<SpinLock<OrderState>>,
    }

    impl BaselineEndpointProvider for OrderedEndpoint {
        type Error = ();

        fn dispatch_or_recover_tool(&mut self) -> Result<(), Self::Error> {
            self.state.lock().endpoint_applied = true;
            Ok(())
        }

        fn verified_tool_finalizer(
            &mut self,
            epoch: u64,
        ) -> Result<BaselineFinalizer, Self::Error> {
            let binding = self.record.tool_binding();
            Ok(BaselineFinalizer::Tool(
                ToolFinalizer::from_receipt(
                    &AcceptTool,
                    BaselineToolReceipt::observed(
                        self.record.effect(),
                        epoch,
                        binding.operation_key(),
                        binding.payload_digest(),
                        binding.endpoint_record_digest(),
                        ToolOutcome::Succeeded,
                    ),
                )
                .unwrap(),
            ))
        }
    }

    struct OrderedDma {
        record: BaselineRecord,
        state: Arc<SpinLock<OrderState>>,
    }

    impl BaselineDmaProvider for OrderedDma {
        type Error = ();

        fn publish_dma_visible(&mut self) -> Result<(), Self::Error> {
            self.state.lock().dma_published = true;
            Ok(())
        }

        fn verified_dma_finalizer(&mut self, epoch: u64) -> Result<BaselineFinalizer, Self::Error> {
            Ok(BaselineFinalizer::Dma(
                DmaFinalizer::from_receipt(
                    &AcceptDma,
                    BaselineDmaReceipt::observed(
                        self.record.effect(),
                        epoch,
                        self.record.resource(),
                        self.record.generation(),
                        true,
                        true,
                        true,
                    ),
                )
                .unwrap(),
            ))
        }
    }

    struct OrderedHook(Arc<SpinLock<OrderState>>);

    impl BaselineCrashHook for OrderedHook {
        type Error = ();

        fn reached(&mut self, cutpoint: BaselineCutpoint) -> Result<(), Self::Error> {
            let mut state = self.0.lock();
            match cutpoint {
                BaselineCutpoint::TopologyDurable | BaselineCutpoint::IntentsDurable => {
                    assert!(state.dma_published);
                    assert!(!state.endpoint_applied);
                }
                BaselineCutpoint::EndpointPostApplied | BaselineCutpoint::DmaPublished => {
                    assert!(state.dma_published && state.endpoint_applied);
                }
                BaselineCutpoint::ToolOutcomeDurable
                | BaselineCutpoint::ReconciliationIntentDurable
                | BaselineCutpoint::RetirementsAndGateDurable => {}
            }
            state.barriers.push(cutpoint.id());
            Ok(())
        }
    }

    #[ktest]
    fn crash_matrix_is_closed_and_stably_numbered() {
        assert_eq!(BaselineCutpoint::TopologyDurable.id(), 1);
        assert_eq!(BaselineCutpoint::IntentsDurable.id(), 2);
        assert_eq!(BaselineCutpoint::EndpointPostApplied.id(), 3);
        assert_eq!(BaselineCutpoint::DmaPublished.id(), 4);
        assert_eq!(BaselineCutpoint::ToolOutcomeDurable.id(), 5);
        assert_eq!(BaselineCutpoint::ReconciliationIntentDurable.id(), 6);
        assert_eq!(BaselineCutpoint::RetirementsAndGateDurable.id(), 7);
    }

    #[ktest]
    fn metrics_never_admit_reuse_before_both_evidence_classes() {
        let mut metrics = BaselineMetrics {
            topology_registered: true,
            reuse_authorized: true,
            ..Default::default()
        };
        assert!(!metrics.invariants_hold());
        metrics.tool_finalized = true;
        metrics.dma_finalized = true;
        assert!(metrics.invariants_hold());
    }

    #[ktest]
    fn recovered_metrics_are_durable_trial_totals_not_boot_local_events() {
        let metrics = BaselineMetrics::from_durable_record(
            super::super::core_baseline_runtime::closed_record_for_experiment_metrics_test(),
        );
        assert!(metrics.topology_registered);
        assert!(metrics.tool_finalized);
        assert!(metrics.dma_finalized);
        assert!(metrics.reuse_authorized);
        assert_eq!(metrics.reconciliation_steps, 1);
        assert_eq!(metrics.retired_by_evidence, 2);
        assert_eq!(metrics.retained_claims, 0);
        // Historical rejections are not present in the durable record; zero
        // therefore means "this recovery boot observed none", not a claim
        // about earlier boot attempts.
        assert_eq!(metrics.gate_rejections, 0);
    }

    #[ktest]
    fn recovered_metrics_remove_each_claim_when_its_finalizer_runs() {
        let mut metrics = BaselineMetrics {
            retained_claims: 2,
            topology_registered: true,
            ..Default::default()
        };
        metrics.record(BaselineExperimentEvent::ToolFinalized {
            effect: 1,
            outcome: super::super::core_baseline_runtime::ToolOutcome::Succeeded,
        });
        assert_eq!(metrics.retained_claims, 1);
        metrics.record(BaselineExperimentEvent::DmaFinalized {
            effect: 1,
            reset_generation: 2,
        });
        assert_eq!(metrics.retained_claims, 0);
        assert_eq!(metrics.retired_by_evidence, 2);
    }

    #[ktest]
    fn common_prefix_durably_acks_dma_before_the_first_two_markers() {
        let record = BaselineRecord::register(
            super::super::core_baseline_runtime::BaselineEffectId::new(11).unwrap(),
            super::super::core_baseline_runtime::BaselineResourceId::new(12).unwrap(),
            13,
            1,
        )
        .unwrap();
        let state = Arc::new(SpinLock::new(OrderState::default()));
        let mut arm = BaselineExperimentArm::new(record);
        let mut endpoint = OrderedEndpoint {
            record,
            state: Arc::clone(&state),
        };
        let mut dma = OrderedDma {
            record,
            state: Arc::clone(&state),
        };
        let mut hook = OrderedHook(Arc::clone(&state));
        arm.execute(&mut endpoint, &mut dma, &mut hook).unwrap();
        assert_eq!(state.lock().barriers.as_slice(), &[1, 2, 3, 4, 5, 6, 7]);
    }
}
