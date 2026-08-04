// SPDX-License-Identifier: MPL-2.0

//! Independent, workload-specific comparison runtime for the CSER experiment.
//!
//! This module deliberately does **not** use the CSER catalog, engine, claim,
//! or permit APIs.  It captures a strong reconstructed finalizer baseline:
//! atomically register the whole fixed topology before either escaped action,
//! keep independent tool and DMA finalizers, fence an exited executor by epoch,
//! and permit generation reuse only after both finalizers have closed.
//!
//! It is a small durable state core, not yet a device driver.  An eventual
//! adapter supplies ATA/TPM/VirtIO operations at the marked boundaries and
//! reports the same [`BaselineExperimentEvent`] stream as the CSER runner.

extern crate alloc;

use alloc::vec::Vec;

const RECORD_MAGIC: [u8; 8] = *b"NEXBASE1";
const RECORD_VERSION: u16 = 3;
pub(crate) const BASELINE_RECORD_BYTES: usize = 256;
const CHECKSUM_OFFSET: usize = BASELINE_RECORD_BYTES - 8;

/// Stable identity of the one fixed comparison workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BaselineEffectId(u64);

impl BaselineEffectId {
    pub(crate) const fn new(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

/// The only resource coordinate used by the comparison workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BaselineResourceId(u64);

impl BaselineResourceId {
    pub(crate) const fn new(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

/// Opaque operation identity selected before the tool endpoint observes work.
///
/// It is deliberately distinct from the effect identity: one effect can have
/// several logical components, while this baseline has exactly one tool
/// operation to reconcile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BaselineOperationKey(u64);

impl BaselineOperationKey {
    pub(crate) const fn new(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }

    /// Stable, non-authoritative projection of the bounded ASCII endpoint
    /// operation key.  The endpoint record verifier still authenticates the
    /// full key; this value merely lets the fixed-width baseline journal bind
    /// that key before the first POST.
    pub(crate) fn from_operation_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        let value = bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
        Self::new(value)
    }
}

/// Fixed-width endpoint binding material.
///
/// This is an equality token, not an integrity primitive.  The independent
/// receipt verifier establishes its authenticity before a finalizer can carry
/// it into the durable baseline state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BaselineDigest([u8; 32]);

impl BaselineDigest {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) const fn zero() -> Self {
        Self([0; 32])
    }

    pub(crate) fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }

    const fn synthetic(domain: u8, identity: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[0] = domain;
        bytes[24] = identity as u8;
        bytes[25] = (identity >> 8) as u8;
        bytes[26] = (identity >> 16) as u8;
        bytes[27] = (identity >> 24) as u8;
        bytes[28] = (identity >> 32) as u8;
        bytes[29] = (identity >> 40) as u8;
        bytes[30] = (identity >> 48) as u8;
        bytes[31] = (identity >> 56) as u8;
        Self(bytes)
    }
}

/// Tool operation fields which a terminal tool receipt must bind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BaselineToolBinding {
    operation_key: BaselineOperationKey,
    payload_digest: BaselineDigest,
    endpoint_record_digest: BaselineDigest,
}

impl BaselineToolBinding {
    pub(crate) const fn new(
        operation_key: BaselineOperationKey,
        payload_digest: BaselineDigest,
        endpoint_record_digest: BaselineDigest,
    ) -> Self {
        Self {
            operation_key,
            payload_digest,
            endpoint_record_digest,
        }
    }

    pub(crate) const fn operation_key(self) -> BaselineOperationKey {
        self.operation_key
    }

    pub(crate) const fn payload_digest(self) -> BaselineDigest {
        self.payload_digest
    }

    pub(crate) const fn endpoint_record_digest(self) -> BaselineDigest {
        self.endpoint_record_digest
    }

    /// Endpoint terminal records do not exist before POST.  A zero digest
    /// means the independent terminal-record verifier, rather than topology
    /// registration, binds the eventual durable endpoint row.
    pub(crate) const fn unbound_endpoint(
        operation_key: BaselineOperationKey,
        payload_digest: BaselineDigest,
    ) -> Self {
        Self::new(operation_key, payload_digest, BaselineDigest::zero())
    }

    const fn default_for(effect: BaselineEffectId) -> Self {
        // The fixed comparison workload has one statically named operation.
        // Adapters should use `register_with_tool_binding` with their actual
        // endpoint material instead.
        Self {
            operation_key: BaselineOperationKey(effect.get()),
            payload_digest: BaselineDigest::synthetic(1, effect.get()),
            endpoint_record_digest: BaselineDigest::synthetic(2, effect.get()),
        }
    }
}

/// Durable, atomic registration of both escaped components.
///
/// `topology_registered` is written in the same double-bank record as both
/// finalizer bits.  A recovery never has to infer that a DMA action exists
/// from a separately persisted tool record (or vice versa).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BaselineRecord {
    effect: BaselineEffectId,
    resource: BaselineResourceId,
    tool_binding: BaselineToolBinding,
    executor: u64,
    fence_epoch: u64,
    generation: u64,
    topology_registered: bool,
    executor_fenced: bool,
    tool_dispatched: bool,
    endpoint_applied: bool,
    tool_finalized: bool,
    dma_dispatched: bool,
    dma_published: bool,
    dma_finalized: bool,
    reconciliation_intent_recorded: bool,
    reuse_generation: Option<u64>,
}

impl BaselineRecord {
    /// Creates a fully registered topology before either endpoint is allowed
    /// to observe work.  Callers must durably persist this record first.
    pub(crate) fn register(
        effect: BaselineEffectId,
        resource: BaselineResourceId,
        executor: u64,
        generation: u64,
    ) -> Result<Self, BaselineError> {
        Self::register_with_tool_binding(
            effect,
            resource,
            executor,
            generation,
            BaselineToolBinding::default_for(effect),
        )
    }

    /// Registers the fixed topology with the tool operation identity that the
    /// independent endpoint verifier must later attest.
    pub(crate) fn register_with_tool_binding(
        effect: BaselineEffectId,
        resource: BaselineResourceId,
        executor: u64,
        generation: u64,
        tool_binding: BaselineToolBinding,
    ) -> Result<Self, BaselineError> {
        if executor == 0 || generation == 0 {
            return Err(BaselineError::InvalidIdentity);
        }
        Ok(Self {
            effect,
            resource,
            tool_binding,
            executor,
            fence_epoch: 1,
            generation,
            topology_registered: true,
            executor_fenced: false,
            tool_dispatched: false,
            endpoint_applied: false,
            tool_finalized: false,
            dma_dispatched: false,
            dma_published: false,
            dma_finalized: false,
            reconciliation_intent_recorded: false,
            reuse_generation: None,
        })
    }

    pub(crate) const fn effect(self) -> BaselineEffectId {
        self.effect
    }
    pub(crate) const fn resource(self) -> BaselineResourceId {
        self.resource
    }
    pub(crate) const fn tool_binding(self) -> BaselineToolBinding {
        self.tool_binding
    }
    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
    pub(crate) const fn fence_epoch(self) -> u64 {
        self.fence_epoch
    }
    pub(crate) const fn tool_finalized(self) -> bool {
        self.tool_finalized
    }
    pub(crate) const fn dma_finalized(self) -> bool {
        self.dma_finalized
    }
    pub(crate) const fn reusable(self) -> bool {
        self.topology_registered
            && self.executor_fenced
            && self.tool_finalized
            && self.reconciliation_intent_recorded
            && self.dma_finalized
    }

    pub(crate) const fn topology_registered(self) -> bool {
        self.topology_registered
    }
    pub(crate) const fn tool_dispatched(self) -> bool {
        self.tool_dispatched
    }
    pub(crate) const fn dma_dispatched(self) -> bool {
        self.dma_dispatched
    }
    pub(crate) const fn endpoint_applied(self) -> bool {
        self.endpoint_applied
    }
    pub(crate) const fn dma_published(self) -> bool {
        self.dma_published
    }
    pub(crate) const fn reconciliation_intent_recorded(self) -> bool {
        self.reconciliation_intent_recorded
    }

    /// A durable reuse reservation is the baseline's terminal gate decision.
    /// It is distinct from the derived `reusable` predicate: a recovered
    /// record must report only a gate that was actually persisted.
    pub(crate) const fn reuse_authorized(self) -> bool {
        self.reuse_generation.is_some()
    }
}

/// Evidence understood by this deliberately narrow baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BaselineFinalizer {
    Tool(ToolFinalizer),
    Dma(DmaFinalizer),
}

/// Query/reconciliation result for the tool endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolFinalizer {
    receipt: BaselineToolReceipt,
}

impl ToolFinalizer {
    /// Obtains finalization authority only from an independently verified
    /// terminal endpoint receipt.  Callers cannot close a tool component by
    /// supplying a `ToolOutcome` alone.
    pub(crate) fn from_receipt<V: BaselineToolReceiptVerifier>(
        verifier: &V,
        receipt: BaselineToolReceipt,
    ) -> Result<Self, BaselineError> {
        verifier.verify_tool_receipt(&receipt)?;
        Ok(Self { receipt })
    }
}

/// Quiescence observation for the DMA endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DmaFinalizer {
    receipt: BaselineDmaReceipt,
}

impl DmaFinalizer {
    /// Obtains finalization authority only from an independently verified
    /// quiescence receipt.  A reset generation by itself is not evidence that
    /// the device stopped accessing the predecessor coordinate.
    pub(crate) fn from_receipt<V: BaselineDmaReceiptVerifier>(
        verifier: &V,
        receipt: BaselineDmaReceipt,
    ) -> Result<Self, BaselineError> {
        verifier.verify_dma_receipt(&receipt)?;
        Ok(Self { receipt })
    }
}

/// Terminal result reported by the tool endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolOutcome {
    Succeeded,
    Failed,
}

/// A terminal tool receipt before it is admitted to a finalizer.
///
/// The receipt binds endpoint identity and operation contents as well as the
/// effect and fence epoch.  It is useful only through
/// [`BaselineToolReceiptVerifier`], which checks the endpoint-specific proof
/// (for example a signed poll result or durable endpoint row).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BaselineToolReceipt {
    effect: BaselineEffectId,
    epoch: u64,
    operation_key: BaselineOperationKey,
    payload_digest: BaselineDigest,
    endpoint_record_digest: BaselineDigest,
    outcome: ToolOutcome,
}

impl BaselineToolReceipt {
    /// Constructs an observed receipt for an independent verifier to inspect.
    /// This constructor grants no finalization authority; `ToolFinalizer`
    /// requires verifier acceptance and the runtime rechecks every binding.
    pub(crate) const fn observed(
        effect: BaselineEffectId,
        epoch: u64,
        operation_key: BaselineOperationKey,
        payload_digest: BaselineDigest,
        endpoint_record_digest: BaselineDigest,
        outcome: ToolOutcome,
    ) -> Self {
        Self {
            effect,
            epoch,
            operation_key,
            payload_digest,
            endpoint_record_digest,
            outcome,
        }
    }

    pub(crate) const fn epoch(self) -> u64 {
        self.epoch
    }
}

/// Independent endpoint-specific verifier for tool terminal receipts.
///
/// This trait intentionally belongs to the baseline module and has no CSER
/// dependency.  A concrete adapter owns the trust decision and must reject
/// unsigned, stale, or otherwise unverifiable endpoint observations.
pub(crate) trait BaselineToolReceiptVerifier {
    fn verify_tool_receipt(&self, receipt: &BaselineToolReceipt) -> Result<(), BaselineError>;
}

/// Device quiescence receipt before it is admitted to a finalizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BaselineDmaReceipt {
    effect: BaselineEffectId,
    epoch: u64,
    resource: BaselineResourceId,
    generation: u64,
    reset_completed: bool,
    irq_drained: bool,
    iotlb_invalidated: bool,
}

impl BaselineDmaReceipt {
    /// Constructs a device observation for an independent verifier to inspect.
    /// The observation cannot by itself authorize finalization.
    pub(crate) const fn observed(
        effect: BaselineEffectId,
        epoch: u64,
        resource: BaselineResourceId,
        generation: u64,
        reset_completed: bool,
        irq_drained: bool,
        iotlb_invalidated: bool,
    ) -> Self {
        Self {
            effect,
            epoch,
            resource,
            generation,
            reset_completed,
            irq_drained,
            iotlb_invalidated,
        }
    }

    /// Converts the shared live-VirtIO closure into this baseline's *own* raw
    /// receipt.  The baseline does not receive a CSER verifier or command:
    /// it only rechecks the independently retained production evidence before
    /// recording its local reset/IRQ/IOTLB facts.
    pub(crate) fn from_live_evidence(
        effect: BaselineEffectId,
        epoch: u64,
        resource: BaselineResourceId,
        generation: u64,
        evidence: super::core_experiment_dma_flow::BaselineRawDmaEvidence,
    ) -> Result<Self, BaselineError> {
        if epoch == 0
            || evidence.resource().resource() != resource.get()
            || evidence.resource().generation() != generation
            || evidence.successor_generation() <= generation
            || evidence.completed_pages() != 3
            || !evidence.irq().cause().includes_queue()
        {
            return Err(BaselineError::ReceiptRejected);
        }
        Ok(Self::observed(
            effect, epoch, resource, generation, true, true, true,
        ))
    }

    const fn complete(self) -> bool {
        self.reset_completed && self.irq_drained && self.iotlb_invalidated
    }

    pub(crate) const fn epoch(self) -> u64 {
        self.epoch
    }

    pub(crate) const fn resource(self) -> BaselineResourceId {
        self.resource
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

/// Independent device-specific verifier for DMA quiescence receipts.
pub(crate) trait BaselineDmaReceiptVerifier {
    fn verify_dma_receipt(&self, receipt: &BaselineDmaReceipt) -> Result<(), BaselineError>;
}

/// Durable authority returned only after the entire predecessor topology is closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BaselineReuseGate {
    resource: BaselineResourceId,
    predecessor_generation: u64,
    successor_generation: u64,
    fenced_epoch: u64,
}

impl BaselineReuseGate {
    pub(crate) const fn successor_generation(self) -> u64 {
        self.successor_generation
    }
    pub(crate) const fn predecessor_generation(self) -> u64 {
        self.predecessor_generation
    }
}

/// Events consumed by the common experiment recorder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BaselineExperimentEvent {
    TopologyRegistered { effect: u64, generation: u64 },
    ToolDispatched { effect: u64 },
    DmaDispatched { effect: u64 },
    ExecutorFenced { effect: u64, epoch: u64 },
    ReconciliationIntentRecorded { effect: u64 },
    ToolFinalized { effect: u64, outcome: ToolOutcome },
    DmaFinalized { effect: u64, reset_generation: u64 },
    ReuseWithheld { effect: u64 },
    ReuseAuthorized { resource: u64, generation: u64 },
}

/// An experiment sink is intentionally transport-neutral: the QEMU runner can
/// print it, while a host fault-injection harness can collect it in memory.
pub(crate) trait BaselineExperimentSink {
    fn record(&mut self, event: BaselineExperimentEvent);
}

/// Small in-memory sink useful to unit/ktests and adapters.
#[derive(Default)]
pub(crate) struct BaselineEventLog {
    events: Vec<BaselineExperimentEvent>,
}

impl BaselineEventLog {
    pub(crate) fn events(&self) -> &[BaselineExperimentEvent] {
        &self.events
    }
}

impl BaselineExperimentSink for BaselineEventLog {
    fn record(&mut self, event: BaselineExperimentEvent) {
        self.events.push(event);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BaselineError {
    InvalidIdentity,
    NotRegistered,
    AlreadyDispatched,
    NotDispatched,
    NotFinalized,
    EndpointNotApplied,
    DmaNotPublished,
    AlreadyFinalized,
    WrongEffect,
    StaleEpoch,
    WrongToolOperationKey,
    WrongToolPayloadDigest,
    WrongEndpointRecordDigest,
    WrongDmaResource,
    WrongDmaGeneration,
    IncompleteDmaQuiescence,
    ReceiptRejected,
    InvalidDmaGeneration,
    NotFenced,
    NotClosed,
    ReuseAlreadyReserved,
    RecordCorrupt,
}

/// Double-bank, checksummed durable cell.
///
/// A backing ATA/TPM implementation can map `write_inactive` and
/// `publish_selector` to its own flush/readback protocol.  This in-memory
/// implementation is deliberately deterministic for the baseline tests.
#[derive(Clone)]
pub(crate) struct BaselineDoubleBank {
    banks: [[u8; BASELINE_RECORD_BYTES]; 2],
    selector: u64,
}

impl BaselineDoubleBank {
    pub(crate) fn initialize(record: BaselineRecord) -> Self {
        let encoded = encode_baseline_record(record, 1);
        Self {
            banks: [[0; BASELINE_RECORD_BYTES], encoded],
            selector: 1,
        }
    }

    pub(crate) fn recover(&self) -> Result<BaselineRecord, BaselineError> {
        let selected = (self.selector & 1) as usize;
        decode_baseline_record(&self.banks[selected], self.selector).or_else(|_| {
            decode_baseline_record(&self.banks[1 - selected], self.selector.saturating_sub(1))
        })
    }

    fn persist(&mut self, record: BaselineRecord) -> Result<(), BaselineError> {
        let next = self
            .selector
            .checked_add(1)
            .ok_or(BaselineError::RecordCorrupt)?;
        let inactive = (next & 1) as usize;
        let encoded = encode_baseline_record(record, next);
        self.banks[inactive] = encoded;
        // Readback validation precedes publication of the selector.
        decode_baseline_record(&self.banks[inactive], next)?;
        self.selector = next;
        Ok(())
    }
}

/// Durable record backend used by the independent finalizer state machine.
///
/// This carries only the fixed baseline record, so an experiment can reuse
/// ATA/TPM durability without acquiring a CSER journal or engine authority.
pub(crate) trait BaselineDurableStore {
    fn recover(&mut self) -> Result<BaselineRecord, BaselineError>;
    fn persist(&mut self, record: BaselineRecord) -> Result<(), BaselineError>;
}

impl BaselineDurableStore for BaselineDoubleBank {
    fn recover(&mut self) -> Result<BaselineRecord, BaselineError> {
        Self::recover(self)
    }

    fn persist(&mut self, record: BaselineRecord) -> Result<(), BaselineError> {
        Self::persist(self, record)
    }
}

/// State-machine facade used by the independent baseline runner.
pub(crate) struct BaselineRuntime<D, S> {
    durable: D,
    sink: S,
}

impl<S: BaselineExperimentSink> BaselineRuntime<BaselineDoubleBank, S> {
    pub(crate) fn new(record: BaselineRecord, mut sink: S) -> Self {
        sink.record(BaselineExperimentEvent::TopologyRegistered {
            effect: record.effect.get(),
            generation: record.generation,
        });
        Self {
            durable: BaselineDoubleBank::initialize(record),
            sink,
        }
    }

    pub(crate) fn recover(mut durable: BaselineDoubleBank, sink: S) -> Result<Self, BaselineError> {
        BaselineDurableStore::recover(&mut durable)?;
        Ok(Self { durable, sink })
    }
}

impl<D: BaselineDurableStore, S: BaselineExperimentSink> BaselineRuntime<D, S> {
    /// Registers the complete topology through a caller-owned durable store.
    ///
    /// This is deliberately separate from the in-memory test constructor:
    /// the first visible event is emitted only after the ATA/TPM-backed store
    /// has accepted the complete record.
    pub(crate) fn initialize_durable(
        mut durable: D,
        record: BaselineRecord,
        mut sink: S,
    ) -> Result<Self, BaselineError> {
        durable.persist(record)?;
        sink.record(BaselineExperimentEvent::TopologyRegistered {
            effect: record.effect.get(),
            generation: record.generation,
        });
        Ok(Self { durable, sink })
    }

    pub(crate) fn from_durable(mut durable: D, sink: S) -> Result<Self, BaselineError> {
        durable.recover()?;
        Ok(Self { durable, sink })
    }

    pub(crate) fn snapshot(&mut self) -> Result<BaselineRecord, BaselineError> {
        self.durable.recover()
    }
    pub(crate) fn into_durable(self) -> D {
        self.durable
    }
    pub(crate) fn sink(&self) -> &S {
        &self.sink
    }

    pub(crate) fn dispatch_tool(&mut self) -> Result<(), BaselineError> {
        let mut record = self.snapshot()?;
        if !record.topology_registered {
            return Err(BaselineError::NotRegistered);
        }
        if record.tool_dispatched {
            return Err(BaselineError::AlreadyDispatched);
        }
        record.tool_dispatched = true;
        self.durable.persist(record)?;
        self.sink.record(BaselineExperimentEvent::ToolDispatched {
            effect: record.effect.get(),
        });
        Ok(())
    }

    pub(crate) fn dispatch_dma(&mut self) -> Result<(), BaselineError> {
        let mut record = self.snapshot()?;
        if !record.topology_registered {
            return Err(BaselineError::NotRegistered);
        }
        if record.dma_dispatched {
            return Err(BaselineError::AlreadyDispatched);
        }
        record.dma_dispatched = true;
        self.durable.persist(record)?;
        self.sink.record(BaselineExperimentEvent::DmaDispatched {
            effect: record.effect.get(),
        });
        Ok(())
    }

    /// Makes both escaped actions durably outstanding in one record update.
    ///
    /// The fixed comparison workload has no meaningful intermediate topology:
    /// once either action can be observed, recovery must retain both.  Keeping
    /// these two bits in one durable transition also makes crash cutpoint two
    /// name a real state rather than a window between two unrelated writes.
    pub(crate) fn dispatch_tool_and_dma(&mut self) -> Result<(), BaselineError> {
        let mut record = self.snapshot()?;
        if !record.topology_registered {
            return Err(BaselineError::NotRegistered);
        }
        if record.tool_dispatched || record.dma_dispatched {
            return Err(BaselineError::AlreadyDispatched);
        }
        record.tool_dispatched = true;
        record.dma_dispatched = true;
        self.durable.persist(record)?;
        self.sink.record(BaselineExperimentEvent::ToolDispatched {
            effect: record.effect.get(),
        });
        self.sink.record(BaselineExperimentEvent::DmaDispatched {
            effect: record.effect.get(),
        });
        Ok(())
    }

    /// Stops admission for the departed executor and advances its epoch.
    pub(crate) fn fence_executor(&mut self) -> Result<u64, BaselineError> {
        let mut record = self.snapshot()?;
        if record.executor_fenced {
            return Ok(record.fence_epoch);
        }
        record.executor_fenced = true;
        record.fence_epoch = record
            .fence_epoch
            .checked_add(1)
            .ok_or(BaselineError::RecordCorrupt)?;
        self.durable.persist(record)?;
        self.sink.record(BaselineExperimentEvent::ExecutorFenced {
            effect: record.effect.get(),
            epoch: record.fence_epoch,
        });
        Ok(record.fence_epoch)
    }

    /// Durably records that the immutable tool operation is externally
    /// visible. This is not its outcome: recovery must still query the
    /// endpoint rather than infer success from executor exit.
    pub(crate) fn record_endpoint_applied(&mut self) -> Result<(), BaselineError> {
        let mut record = self.snapshot()?;
        if !record.tool_dispatched {
            return Err(BaselineError::NotDispatched);
        }
        if !record.endpoint_applied {
            record.endpoint_applied = true;
            self.durable.persist(record)?;
        }
        Ok(())
    }

    /// Durably records device-visible DMA publication. It is deliberately
    /// distinct from reset/drain/IOTLB quiescence, which retires later.
    pub(crate) fn record_dma_published(&mut self) -> Result<(), BaselineError> {
        let mut record = self.snapshot()?;
        if !record.dma_dispatched {
            return Err(BaselineError::NotDispatched);
        }
        if !record.dma_published {
            record.dma_published = true;
            self.durable.persist(record)?;
        }
        Ok(())
    }

    /// Durable reconciliation/apply intent after a verified logical outcome.
    pub(crate) fn record_reconciliation_intent(&mut self) -> Result<(), BaselineError> {
        let mut record = self.snapshot()?;
        if !record.tool_finalized {
            return Err(BaselineError::NotFinalized);
        }
        if !record.reconciliation_intent_recorded {
            record.reconciliation_intent_recorded = true;
            self.durable.persist(record)?;
            self.sink
                .record(BaselineExperimentEvent::ReconciliationIntentRecorded {
                    effect: record.effect.get(),
                });
        }
        Ok(())
    }

    pub(crate) fn finalize(&mut self, finalizer: BaselineFinalizer) -> Result<(), BaselineError> {
        let mut record = self.snapshot()?;
        let (effect, epoch) = match finalizer {
            BaselineFinalizer::Tool(value) => (value.receipt.effect, value.receipt.epoch),
            BaselineFinalizer::Dma(value) => (value.receipt.effect, value.receipt.epoch),
        };
        if effect != record.effect {
            return Err(BaselineError::WrongEffect);
        }
        if epoch != record.fence_epoch {
            return Err(BaselineError::StaleEpoch);
        }
        if !record.executor_fenced {
            return Err(BaselineError::NotFenced);
        }
        match finalizer {
            BaselineFinalizer::Tool(value) => {
                if !record.tool_dispatched {
                    return Err(BaselineError::NotDispatched);
                }
                if !record.endpoint_applied {
                    return Err(BaselineError::EndpointNotApplied);
                }
                if record.tool_finalized {
                    return Err(BaselineError::AlreadyFinalized);
                }
                if value.receipt.operation_key != record.tool_binding.operation_key {
                    return Err(BaselineError::WrongToolOperationKey);
                }
                if value.receipt.payload_digest != record.tool_binding.payload_digest {
                    return Err(BaselineError::WrongToolPayloadDigest);
                }
                if value.receipt.endpoint_record_digest.is_zero()
                    || (!record.tool_binding.endpoint_record_digest.is_zero()
                        && value.receipt.endpoint_record_digest
                            != record.tool_binding.endpoint_record_digest)
                {
                    return Err(BaselineError::WrongEndpointRecordDigest);
                }
                record.tool_finalized = true;
                self.durable.persist(record)?;
                self.sink.record(BaselineExperimentEvent::ToolFinalized {
                    effect: record.effect.get(),
                    outcome: value.receipt.outcome,
                });
            }
            BaselineFinalizer::Dma(value) => {
                if !record.dma_dispatched {
                    return Err(BaselineError::NotDispatched);
                }
                if !record.dma_published {
                    return Err(BaselineError::DmaNotPublished);
                }
                if record.dma_finalized {
                    return Err(BaselineError::AlreadyFinalized);
                }
                if value.receipt.resource != record.resource {
                    return Err(BaselineError::WrongDmaResource);
                }
                if value.receipt.generation != record.generation {
                    return Err(BaselineError::WrongDmaGeneration);
                }
                if !value.receipt.complete() {
                    return Err(BaselineError::IncompleteDmaQuiescence);
                }
                if value.receipt.generation == u64::MAX {
                    return Err(BaselineError::InvalidDmaGeneration);
                }
                record.dma_finalized = true;
                self.durable.persist(record)?;
                self.sink.record(BaselineExperimentEvent::DmaFinalized {
                    effect: record.effect.get(),
                    reset_generation: value.receipt.generation + 1,
                });
            }
        }
        Ok(())
    }

    pub(crate) fn reserve_reuse(&mut self) -> Result<BaselineReuseGate, BaselineError> {
        let mut record = self.snapshot()?;
        if !record.reusable() {
            self.sink.record(BaselineExperimentEvent::ReuseWithheld {
                effect: record.effect.get(),
            });
            return Err(BaselineError::NotClosed);
        }
        if record.reuse_generation.is_some() {
            return Err(BaselineError::ReuseAlreadyReserved);
        }
        let successor = record
            .generation
            .checked_add(1)
            .ok_or(BaselineError::RecordCorrupt)?;
        record.reuse_generation = Some(successor);
        self.durable.persist(record)?;
        let gate = BaselineReuseGate {
            resource: record.resource,
            predecessor_generation: record.generation,
            successor_generation: successor,
            fenced_epoch: record.fence_epoch,
        };
        self.sink.record(BaselineExperimentEvent::ReuseAuthorized {
            resource: gate.resource.get(),
            generation: successor,
        });
        Ok(gate)
    }

    /// Reconstructs the already durable reuse decision after a crash at the
    /// final cutpoint.  This is not a new authorization: the returned value
    /// is derived only from a record that is fully closed and whose successor
    /// generation was atomically persisted by `reserve_reuse`.
    pub(crate) fn recovered_reuse_gate(
        &mut self,
    ) -> Result<Option<BaselineReuseGate>, BaselineError> {
        let record = self.snapshot()?;
        let Some(successor_generation) = record.reuse_generation else {
            return Ok(None);
        };
        if !record.reusable()
            || successor_generation
                != record
                    .generation
                    .checked_add(1)
                    .ok_or(BaselineError::RecordCorrupt)?
        {
            return Err(BaselineError::RecordCorrupt);
        }
        Ok(Some(BaselineReuseGate {
            resource: record.resource,
            predecessor_generation: record.generation,
            successor_generation,
            fenced_epoch: record.fence_epoch,
        }))
    }
}

pub(crate) fn encode_baseline_record(
    record: BaselineRecord,
    sequence: u64,
) -> [u8; BASELINE_RECORD_BYTES] {
    let mut bytes = [0; BASELINE_RECORD_BYTES];
    bytes[0..8].copy_from_slice(&RECORD_MAGIC);
    put_u16(&mut bytes, 8, RECORD_VERSION);
    put_u64(&mut bytes, 16, sequence);
    put_u64(&mut bytes, 24, record.effect.get());
    put_u64(&mut bytes, 32, record.resource.get());
    put_u64(&mut bytes, 40, record.executor);
    put_u64(&mut bytes, 48, record.fence_epoch);
    put_u64(&mut bytes, 56, record.generation);
    put_u64(&mut bytes, 64, record.reuse_generation.unwrap_or(0));
    put_u64(&mut bytes, 80, record.tool_binding.operation_key.get());
    bytes[88..120].copy_from_slice(&record.tool_binding.payload_digest.0);
    bytes[120..152].copy_from_slice(&record.tool_binding.endpoint_record_digest.0);
    let flags = (record.topology_registered as u16)
        | ((record.executor_fenced as u16) << 1)
        | ((record.tool_dispatched as u16) << 2)
        | ((record.tool_finalized as u16) << 3)
        | ((record.dma_dispatched as u16) << 4)
        | ((record.dma_finalized as u16) << 5)
        | ((record.endpoint_applied as u16) << 6)
        | ((record.dma_published as u16) << 7)
        | ((record.reconciliation_intent_recorded as u16) << 8);
    put_u16(&mut bytes, 72, flags);
    let record_checksum = checksum(&bytes[..CHECKSUM_OFFSET]);
    put_u64(&mut bytes, CHECKSUM_OFFSET, record_checksum);
    bytes
}

pub(crate) fn decode_baseline_record(
    bytes: &[u8; BASELINE_RECORD_BYTES],
    expected_sequence: u64,
) -> Result<BaselineRecord, BaselineError> {
    if bytes[0..8] != RECORD_MAGIC
        || read_u16(bytes, 8) != RECORD_VERSION
        || read_u64(bytes, 16) != expected_sequence
        || read_u64(bytes, CHECKSUM_OFFSET) != checksum(&bytes[..CHECKSUM_OFFSET])
    {
        return Err(BaselineError::RecordCorrupt);
    }
    let effect = BaselineEffectId::new(read_u64(bytes, 24)).ok_or(BaselineError::RecordCorrupt)?;
    let resource =
        BaselineResourceId::new(read_u64(bytes, 32)).ok_or(BaselineError::RecordCorrupt)?;
    let executor = read_u64(bytes, 40);
    let fence_epoch = read_u64(bytes, 48);
    let generation = read_u64(bytes, 56);
    if executor == 0 || fence_epoch == 0 || generation == 0 {
        return Err(BaselineError::RecordCorrupt);
    }
    let flags = read_u16(bytes, 72);
    if flags & !0b1_1111_1111 != 0
        || flags & 1 == 0
        || bytes[10..16].iter().any(|byte| *byte != 0)
        || bytes[74..80].iter().any(|byte| *byte != 0)
        || bytes[152..CHECKSUM_OFFSET].iter().any(|byte| *byte != 0)
    {
        return Err(BaselineError::RecordCorrupt);
    }
    let reuse = read_u64(bytes, 64);
    let operation_key =
        BaselineOperationKey::new(read_u64(bytes, 80)).ok_or(BaselineError::RecordCorrupt)?;
    let mut payload_digest = [0; 32];
    payload_digest.copy_from_slice(&bytes[88..120]);
    let mut endpoint_record_digest = [0; 32];
    endpoint_record_digest.copy_from_slice(&bytes[120..152]);
    let record = BaselineRecord {
        effect,
        resource,
        tool_binding: BaselineToolBinding::new(
            operation_key,
            BaselineDigest::new(payload_digest),
            BaselineDigest::new(endpoint_record_digest),
        ),
        executor,
        fence_epoch,
        generation,
        topology_registered: flags & 1 != 0,
        executor_fenced: flags & (1 << 1) != 0,
        tool_dispatched: flags & (1 << 2) != 0,
        endpoint_applied: flags & (1 << 6) != 0,
        tool_finalized: flags & (1 << 3) != 0,
        dma_dispatched: flags & (1 << 4) != 0,
        dma_published: flags & (1 << 7) != 0,
        dma_finalized: flags & (1 << 5) != 0,
        reconciliation_intent_recorded: flags & (1 << 8) != 0,
        reuse_generation: if reuse == 0 { None } else { Some(reuse) },
    };
    validate_decoded_record(record)?;
    Ok(record)
}

/// A checked fully-closed record for the experiment metrics regression.  This
/// lives beside the private record representation so the experiment test does
/// not gain a production constructor for terminal state.
#[cfg(any(test, ktest))]
pub(crate) fn closed_record_for_experiment_metrics_test() -> BaselineRecord {
    let effect = BaselineEffectId::new(0x91).expect("test effect is valid");
    let resource = BaselineResourceId::new(0x92).expect("test resource is valid");
    let mut record =
        BaselineRecord::register(effect, resource, 1, 1).expect("test baseline record is valid");
    record.executor_fenced = true;
    record.tool_dispatched = true;
    record.endpoint_applied = true;
    record.tool_finalized = true;
    record.dma_dispatched = true;
    record.dma_published = true;
    record.dma_finalized = true;
    record.reconciliation_intent_recorded = true;
    record.reuse_generation = Some(2);
    record
}

/// Reject combinations which can never be produced by the transition API.
/// Checksums detect torn bytes; these checks prevent a wholly checksummed but
/// semantically impossible image from becoming reuse authority.
fn validate_decoded_record(record: BaselineRecord) -> Result<(), BaselineError> {
    if record.executor_fenced != (record.fence_epoch > 1)
        || (record.endpoint_applied && !record.tool_dispatched)
        || (record.tool_finalized && (!record.tool_dispatched || !record.endpoint_applied))
        || (record.reconciliation_intent_recorded && !record.tool_finalized)
        || (record.dma_published && !record.dma_dispatched)
        || (record.dma_finalized && (!record.dma_dispatched || !record.dma_published))
    {
        return Err(BaselineError::RecordCorrupt);
    }
    if let Some(successor) = record.reuse_generation {
        if !record.reusable()
            || successor
                != record
                    .generation
                    .checked_add(1)
                    .ok_or(BaselineError::RecordCorrupt)?
        {
            return Err(BaselineError::RecordCorrupt);
        }
    }
    Ok(())
}

fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn read_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(
        bytes[at..at + 8]
            .try_into()
            .expect("fixed-width record slice"),
    )
}

/// FNV-1a is an integrity checksum, not a trust anchor.  ATA/TPM adapters
/// provide durability/anti-rollback; this catches torn or misaddressed banks.
fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[cfg(any(test, ktest))]
mod tests {
    use super::*;

    struct AcceptToolReceipt;
    impl BaselineToolReceiptVerifier for AcceptToolReceipt {
        fn verify_tool_receipt(&self, _receipt: &BaselineToolReceipt) -> Result<(), BaselineError> {
            Ok(())
        }
    }

    struct RejectToolReceipt;
    impl BaselineToolReceiptVerifier for RejectToolReceipt {
        fn verify_tool_receipt(&self, _receipt: &BaselineToolReceipt) -> Result<(), BaselineError> {
            Err(BaselineError::ReceiptRejected)
        }
    }

    struct AcceptDmaReceipt;
    impl BaselineDmaReceiptVerifier for AcceptDmaReceipt {
        fn verify_dma_receipt(&self, _receipt: &BaselineDmaReceipt) -> Result<(), BaselineError> {
            Ok(())
        }
    }

    struct EmptyDurableStore {
        record: Option<BaselineRecord>,
        writes: u64,
    }

    impl BaselineDurableStore for EmptyDurableStore {
        fn recover(&mut self) -> Result<BaselineRecord, BaselineError> {
            self.record.ok_or(BaselineError::RecordCorrupt)
        }

        fn persist(&mut self, record: BaselineRecord) -> Result<(), BaselineError> {
            self.writes += 1;
            self.record = Some(record);
            Ok(())
        }
    }

    fn record() -> BaselineRecord {
        BaselineRecord::register(
            BaselineEffectId::new(1).unwrap(),
            BaselineResourceId::new(9).unwrap(),
            7,
            1,
        )
        .unwrap()
    }

    fn tool_receipt(
        record: BaselineRecord,
        epoch: u64,
        outcome: ToolOutcome,
    ) -> BaselineToolReceipt {
        BaselineToolReceipt::observed(
            record.effect,
            epoch,
            record.tool_binding.operation_key,
            record.tool_binding.payload_digest,
            record.tool_binding.endpoint_record_digest,
            outcome,
        )
    }

    fn dma_receipt(record: BaselineRecord, epoch: u64) -> BaselineDmaReceipt {
        BaselineDmaReceipt::observed(
            record.effect,
            epoch,
            record.resource,
            record.generation,
            true,
            true,
            true,
        )
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn topology_is_atomic_and_reuse_waits_for_both_finalizers() {
        let mut runtime = BaselineRuntime::new(record(), BaselineEventLog::default());
        runtime.dispatch_tool().unwrap();
        runtime.dispatch_dma().unwrap();
        runtime.record_endpoint_applied().unwrap();
        runtime.record_dma_published().unwrap();
        let epoch = runtime.fence_executor().unwrap();
        runtime
            .finalize(BaselineFinalizer::Tool(
                ToolFinalizer::from_receipt(
                    &AcceptToolReceipt,
                    tool_receipt(record(), epoch, ToolOutcome::Succeeded),
                )
                .unwrap(),
            ))
            .unwrap();
        assert_eq!(runtime.reserve_reuse(), Err(BaselineError::NotClosed));
        runtime.record_reconciliation_intent().unwrap();
        runtime
            .finalize(BaselineFinalizer::Dma(
                DmaFinalizer::from_receipt(&AcceptDmaReceipt, dma_receipt(record(), epoch))
                    .unwrap(),
            ))
            .unwrap();
        assert_eq!(runtime.reserve_reuse().unwrap().successor_generation(), 2);
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn composite_intents_are_one_durable_transition() {
        let store = EmptyDurableStore {
            record: Some(record()),
            writes: 0,
        };
        let mut runtime =
            BaselineRuntime::from_durable(store, BaselineEventLog::default()).unwrap();
        runtime.dispatch_tool_and_dma().unwrap();
        let durable = runtime.into_durable();
        assert_eq!(durable.writes, 1);
        let record = durable.record.unwrap();
        assert!(record.tool_dispatched && record.dma_dispatched);
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn checksummed_impossible_states_are_rejected() {
        let registered = record();
        let mut bytes = encode_baseline_record(registered, 1);
        // A final tool receipt without a dispatched/applied tool is not a
        // state the transition API can emit. Recompute the checksum so this
        // exercises semantic, rather than torn-write, validation.
        let flags = read_u16(&bytes, 72) | (1 << 3);
        put_u16(&mut bytes, 72, flags);
        put_u64(
            &mut bytes,
            CHECKSUM_OFFSET,
            checksum(&bytes[..CHECKSUM_OFFSET]),
        );
        assert_eq!(
            decode_baseline_record(&bytes, 1),
            Err(BaselineError::RecordCorrupt)
        );
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn stale_finalizer_cannot_close_a_fenced_effect_after_recovery() {
        let mut runtime = BaselineRuntime::new(record(), BaselineEventLog::default());
        runtime.dispatch_tool().unwrap();
        let epoch = runtime.fence_executor().unwrap();
        let durable = runtime.into_durable();
        let mut recovered = BaselineRuntime::recover(durable, BaselineEventLog::default()).unwrap();
        assert_eq!(
            recovered.finalize(BaselineFinalizer::Tool(
                ToolFinalizer::from_receipt(
                    &AcceptToolReceipt,
                    tool_receipt(record(), epoch - 1, ToolOutcome::Succeeded),
                )
                .unwrap(),
            )),
            Err(BaselineError::StaleEpoch)
        );
        assert!(recovered.snapshot().unwrap().topology_registered);
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn recovery_uses_last_published_bank_when_inactive_bank_is_corrupt() {
        let mut durable = BaselineDoubleBank::initialize(record());
        let initial = durable.recover().unwrap();
        durable.persist(record()).unwrap();
        durable.banks[0][0] ^= 1;
        assert_eq!(durable.recover().unwrap(), initial);
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn terminal_outcome_cannot_bypass_the_independent_receipt_verifier() {
        let receipt = tool_receipt(record(), 2, ToolOutcome::Succeeded);
        assert_eq!(
            ToolFinalizer::from_receipt(&RejectToolReceipt, receipt),
            Err(BaselineError::ReceiptRejected)
        );
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn verified_tool_receipt_must_bind_the_registered_operation_and_digests() {
        let registered = record();
        let mut runtime = BaselineRuntime::new(registered, BaselineEventLog::default());
        runtime.dispatch_tool().unwrap();
        runtime.record_endpoint_applied().unwrap();
        let epoch = runtime.fence_executor().unwrap();

        let wrong_key = BaselineToolReceipt::observed(
            registered.effect,
            epoch,
            BaselineOperationKey::new(88).unwrap(),
            registered.tool_binding.payload_digest,
            registered.tool_binding.endpoint_record_digest,
            ToolOutcome::Succeeded,
        );
        assert_eq!(
            runtime.finalize(BaselineFinalizer::Tool(
                ToolFinalizer::from_receipt(&AcceptToolReceipt, wrong_key).unwrap(),
            )),
            Err(BaselineError::WrongToolOperationKey)
        );
        assert!(!runtime.snapshot().unwrap().tool_finalized);

        let wrong_payload = BaselineToolReceipt::observed(
            registered.effect,
            epoch,
            registered.tool_binding.operation_key,
            BaselineDigest::new([3; 32]),
            registered.tool_binding.endpoint_record_digest,
            ToolOutcome::Succeeded,
        );
        assert_eq!(
            runtime.finalize(BaselineFinalizer::Tool(
                ToolFinalizer::from_receipt(&AcceptToolReceipt, wrong_payload).unwrap(),
            )),
            Err(BaselineError::WrongToolPayloadDigest)
        );

        let wrong_endpoint_record = BaselineToolReceipt::observed(
            registered.effect,
            epoch,
            registered.tool_binding.operation_key,
            registered.tool_binding.payload_digest,
            BaselineDigest::new([4; 32]),
            ToolOutcome::Succeeded,
        );
        assert_eq!(
            runtime.finalize(BaselineFinalizer::Tool(
                ToolFinalizer::from_receipt(&AcceptToolReceipt, wrong_endpoint_record).unwrap(),
            )),
            Err(BaselineError::WrongEndpointRecordDigest)
        );
        assert!(!runtime.snapshot().unwrap().tool_finalized);
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn dma_receipt_requires_exact_coordinate_and_all_quiescence_observations() {
        let registered = record();
        let mut runtime = BaselineRuntime::new(registered, BaselineEventLog::default());
        runtime.dispatch_dma().unwrap();
        runtime.record_dma_published().unwrap();
        let epoch = runtime.fence_executor().unwrap();

        let wrong_resource = BaselineDmaReceipt::observed(
            registered.effect,
            epoch,
            BaselineResourceId::new(10).unwrap(),
            registered.generation,
            true,
            true,
            true,
        );
        assert_eq!(
            runtime.finalize(BaselineFinalizer::Dma(
                DmaFinalizer::from_receipt(&AcceptDmaReceipt, wrong_resource).unwrap(),
            )),
            Err(BaselineError::WrongDmaResource)
        );

        let wrong_generation = BaselineDmaReceipt::observed(
            registered.effect,
            epoch,
            registered.resource,
            registered.generation + 1,
            true,
            true,
            true,
        );
        assert_eq!(
            runtime.finalize(BaselineFinalizer::Dma(
                DmaFinalizer::from_receipt(&AcceptDmaReceipt, wrong_generation).unwrap(),
            )),
            Err(BaselineError::WrongDmaGeneration)
        );

        let incomplete = BaselineDmaReceipt::observed(
            registered.effect,
            epoch,
            registered.resource,
            registered.generation,
            true,
            false,
            true,
        );
        assert_eq!(
            runtime.finalize(BaselineFinalizer::Dma(
                DmaFinalizer::from_receipt(&AcceptDmaReceipt, incomplete).unwrap(),
            )),
            Err(BaselineError::IncompleteDmaQuiescence)
        );
        assert!(!runtime.snapshot().unwrap().dma_finalized);
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn durable_phase_boundaries_cannot_be_skipped_before_reuse() {
        let registered = record();
        let mut runtime = BaselineRuntime::new(registered, BaselineEventLog::default());
        runtime.dispatch_tool().unwrap();
        runtime.dispatch_dma().unwrap();
        let epoch = runtime.fence_executor().unwrap();
        let tool = ToolFinalizer::from_receipt(
            &AcceptToolReceipt,
            tool_receipt(registered, epoch, ToolOutcome::Succeeded),
        )
        .unwrap();
        assert_eq!(
            runtime.finalize(BaselineFinalizer::Tool(tool)),
            Err(BaselineError::EndpointNotApplied)
        );

        runtime.record_endpoint_applied().unwrap();
        runtime
            .finalize(BaselineFinalizer::Tool(
                ToolFinalizer::from_receipt(
                    &AcceptToolReceipt,
                    tool_receipt(registered, epoch, ToolOutcome::Succeeded),
                )
                .unwrap(),
            ))
            .unwrap();
        runtime.record_dma_published().unwrap();
        runtime
            .finalize(BaselineFinalizer::Dma(
                DmaFinalizer::from_receipt(&AcceptDmaReceipt, dma_receipt(registered, epoch))
                    .unwrap(),
            ))
            .unwrap();
        assert_eq!(runtime.reserve_reuse(), Err(BaselineError::NotClosed));
        runtime.record_reconciliation_intent().unwrap();
        assert_eq!(runtime.reserve_reuse().unwrap().successor_generation(), 2);
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn durable_initialization_persists_topology_before_exposing_the_runtime() {
        let store = EmptyDurableStore {
            record: None,
            writes: 0,
        };
        let runtime =
            BaselineRuntime::initialize_durable(store, record(), BaselineEventLog::default())
                .unwrap();
        assert_eq!(runtime.into_durable().writes, 1);
    }
}
