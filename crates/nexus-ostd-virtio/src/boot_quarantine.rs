// SPDX-License-Identifier: MPL-2.0

//! Boot-time physical quarantine for the fixed production VirtIO/VT-d fixture.
//!
//! This module is intentionally hardware-only. It does not replay a CSER
//! journal, interpret a domain claim, or decide that a claim may retire.
//! Instead it acquires the unique `00:05.0` owner and establishes four physical
//! facts before a caller can inspect persistent state:
//!
//! 1. PCI `BUS_MASTER` is clear and INTx is masked with exact readback;
//! 2. VirtIO status zero is observed after reset;
//! 3. the VirtIO ISR is read until two consecutive empty observations;
//! 4. a never-device-visible remapped page completes the patched OSTD global
//!    IOTLB invalidation path.
//!
//! The returned guard retains the PCI root and masked INTx token. Typed
//! receipts may later bind these whole-device facts to exact replayed claim
//! coordinates, but they carry no queue, BAR, DMA, or activation authority.

#![allow(clippy::result_large_err)]

use core::hint::spin_loop;

use virtio_drivers::transport::{
    DeviceStatus, DeviceType, InterruptStatus, Transport,
    pci::{PciTransport as RawPciTransport, VirtioPciError},
};

use crate::{
    ProductionDevice, ProductionDeviceClaimError,
    dma::{
        self, BootIotlbObservation, BootIotlbProgress, BootIotlbStartError, BootIotlbTombstone,
        OstdHal,
    },
    pci::{
        self, BootPciFenceError, BootPciFenceObservation, DeviceBdf, MaskedIntx, OwnedPciTransport,
        PciDiscoveryError, Root,
    },
};

type PciTransport = OwnedPciTransport;

const RESET_POLL_LIMIT: usize = 10_000_000;
const IRQ_DRAIN_POLL_LIMIT: usize = 10_000;
const IOTLB_POLL_LIMIT: usize = 10_000_000;
const REQUIRED_EMPTY_ISR_OBSERVATIONS: usize = 2;

/// Stable, descriptive identity of one independently fenced PCI function.
///
/// The encoding matches the portable core's current PCI device-scope rule:
/// `(bus << 16 | device << 8 | function) + 1`. It is not a hardware owner.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BootDeviceScope(u64);

impl BootDeviceScope {
    /// Validates an externally replayed device-scope coordinate.
    pub const fn new(value: u64) -> Result<Self, BootClaimCoordinateError> {
        if value == 0 {
            Err(BootClaimCoordinateError::Zero(
                BootClaimCoordinateField::DeviceScope,
            ))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the stable numeric representation.
    pub const fn get(self) -> u64 {
        self.0
    }

    const fn from_bdf(bdf: DeviceBdf) -> Self {
        let packed = (bdf.bus() as u64) << 16 | (bdf.device() as u64) << 8 | bdf.function() as u64;
        Self(packed + 1)
    }
}

/// Fresh device generation which the trusted boot provider has reserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootQuarantineRequest {
    observed_generation: u64,
}

impl BootQuarantineRequest {
    /// Creates one quarantine request for a non-zero trusted generation.
    pub const fn new(observed_generation: u64) -> Result<Self, BootQuarantineRequestError> {
        if observed_generation == 0 {
            Err(BootQuarantineRequestError::ZeroGeneration)
        } else {
            Ok(Self {
                observed_generation,
            })
        }
    }

    /// Returns the generation which must bind subsequent anchored recovery.
    pub const fn observed_generation(self) -> u64 {
        self.observed_generation
    }
}

/// Invalid caller input before any hardware discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootQuarantineRequestError {
    /// Zero is reserved for an absent device generation.
    ZeroGeneration,
}

/// Exact descriptive coordinates of one replayed claim.
///
/// These fields are not trusted merely because this type exists. A receipt
/// verifier must compare every field with its one-shot core challenge. The
/// boot guard only proves that the whole device scope and old generation named
/// here are covered by its physical reset and global invalidation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootClaimCoordinates {
    scope: BootDeviceScope,
    effect_root: u64,
    effect_sequence: u64,
    component: Option<u32>,
    claim: u64,
    claim_kind: u32,
    resource: u64,
    resource_generation: u64,
    units: u64,
    subject_device_generation: u64,
}

impl BootClaimCoordinates {
    /// Constructs validated replay coordinates.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        scope: BootDeviceScope,
        effect_root: u64,
        effect_sequence: u64,
        claim: u64,
        claim_kind: u32,
        resource: u64,
        resource_generation: u64,
        units: u64,
        subject_device_generation: u64,
    ) -> Result<Self, BootClaimCoordinateError> {
        if effect_root == 0 {
            return Err(BootClaimCoordinateError::Zero(
                BootClaimCoordinateField::EffectRoot,
            ));
        }
        if effect_sequence == 0 {
            return Err(BootClaimCoordinateError::Zero(
                BootClaimCoordinateField::EffectSequence,
            ));
        }
        if claim == 0 {
            return Err(BootClaimCoordinateError::Zero(
                BootClaimCoordinateField::Claim,
            ));
        }
        if claim_kind == 0 {
            return Err(BootClaimCoordinateError::Zero(
                BootClaimCoordinateField::ClaimKind,
            ));
        }
        if resource == 0 {
            return Err(BootClaimCoordinateError::Zero(
                BootClaimCoordinateField::Resource,
            ));
        }
        if resource_generation == 0 {
            return Err(BootClaimCoordinateError::Zero(
                BootClaimCoordinateField::ResourceGeneration,
            ));
        }
        if units == 0 {
            return Err(BootClaimCoordinateError::Zero(
                BootClaimCoordinateField::Units,
            ));
        }
        if subject_device_generation == 0 {
            return Err(BootClaimCoordinateError::Zero(
                BootClaimCoordinateField::SubjectDeviceGeneration,
            ));
        }
        Ok(Self {
            scope,
            effect_root,
            effect_sequence,
            component: None,
            claim,
            claim_kind,
            resource,
            resource_generation,
            units,
            subject_device_generation,
        })
    }

    /// Constructs validated component-local replay coordinates.
    #[allow(clippy::too_many_arguments)]
    pub fn new_component(
        scope: BootDeviceScope,
        effect_root: u64,
        effect_sequence: u64,
        component: u32,
        claim: u64,
        claim_kind: u32,
        resource: u64,
        resource_generation: u64,
        units: u64,
        subject_device_generation: u64,
    ) -> Result<Self, BootClaimCoordinateError> {
        if component == 0 {
            return Err(BootClaimCoordinateError::Zero(
                BootClaimCoordinateField::Component,
            ));
        }
        let mut coordinates = Self::new(
            scope,
            effect_root,
            effect_sequence,
            claim,
            claim_kind,
            resource,
            resource_generation,
            units,
            subject_device_generation,
        )?;
        coordinates.component = Some(component);
        Ok(coordinates)
    }

    /// Returns the stable device reset-domain scope.
    pub const fn scope(self) -> BootDeviceScope {
        self.scope
    }

    /// Returns the causal root component of the effect identity.
    pub const fn effect_root(self) -> u64 {
        self.effect_root
    }

    /// Returns the per-root effect sequence.
    pub const fn effect_sequence(self) -> u64 {
        self.effect_sequence
    }

    /// Returns the optional composite-effect component slot.
    pub const fn component(self) -> Option<u32> {
        self.component
    }

    /// Returns the stable claim identity.
    pub const fn claim(self) -> u64 {
        self.claim
    }

    /// Returns the domain-defined claim kind.
    pub const fn claim_kind(self) -> u32 {
        self.claim_kind
    }

    /// Returns the stable journal resource identity.
    ///
    /// This abstract coordinate is not an exact PFN or IOVA extent.
    pub const fn resource(self) -> u64 {
        self.resource
    }

    /// Returns the allocation generation of the resource.
    pub const fn resource_generation(self) -> u64 {
        self.resource_generation
    }

    /// Returns the retained resource units.
    pub const fn units(self) -> u64 {
        self.units
    }

    /// Returns the dead owner's device generation.
    pub const fn subject_device_generation(self) -> u64 {
        self.subject_device_generation
    }
}

/// Coordinate whose reserved zero value was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootClaimCoordinateField {
    DeviceScope,
    EffectRoot,
    EffectSequence,
    Component,
    Claim,
    ClaimKind,
    Resource,
    ResourceGeneration,
    Units,
    SubjectDeviceGeneration,
}

/// Invalid replay coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootClaimCoordinateError {
    Zero(BootClaimCoordinateField),
}

/// Rejection while binding a whole-device physical observation to one claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootReceiptBindingError {
    /// The claim belongs to another independently reset device.
    ForeignDeviceScope {
        expected: BootDeviceScope,
        observed: BootDeviceScope,
    },
    /// The replayed claim is not older than the freshly fenced boot
    /// generation.
    ///
    /// A retained claim can survive more than one recovery checkpoint, so the
    /// old generation need not be the immediate predecessor. Equality and
    /// future generations remain fail-closed.
    NonOlderGeneration {
        subject: u64,
        observed_boot_generation: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResetDrainObservation {
    pci: BootPciFenceObservation,
    reset_status_zero: bool,
    observed_isr_bits: u32,
    isr_reads: usize,
    consecutive_empty_isr_reads: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BootHardwareEvidence {
    bdf: DeviceBdf,
    scope: BootDeviceScope,
    observed_generation: u64,
    reset: ResetDrainObservation,
    iotlb: BootIotlbObservation,
}

/// Read-only snapshot of the physical facts retained by a boot quarantine.
///
/// This value carries no PCI, queue, DMA, or activation authority. Its fields
/// can only be obtained from a completed [`BootQuarantineGuard`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootQuarantineObservation {
    evidence: BootHardwareEvidence,
}

impl BootQuarantineObservation {
    /// Reports the exact PCI command readback.
    pub const fn bus_master_disabled(self) -> bool {
        self.evidence.reset.pci.bus_master_disabled
    }

    /// Reports the exact PCI INTx mask readback.
    pub const fn intx_masked(self) -> bool {
        self.evidence.reset.pci.intx_masked
    }

    /// Reports the exact VirtIO status-zero observation.
    pub const fn reset_status_zero(self) -> bool {
        self.evidence.reset.reset_status_zero
    }

    /// Returns all VirtIO ISR cause bits observed while draining.
    pub const fn observed_isr_bits(self) -> u32 {
        self.evidence.reset.observed_isr_bits
    }

    /// Returns the number of real VirtIO ISR reads performed.
    pub const fn isr_reads(self) -> usize {
        self.evidence.reset.isr_reads
    }

    /// Returns the terminal consecutive empty ISR-read count.
    pub const fn consecutive_empty_isr_reads(self) -> usize {
        self.evidence.reset.consecutive_empty_isr_reads
    }

    /// Reports that the IOTLB trigger page used an actual remapped IOVA.
    pub const fn iotlb_used_remapped_iova(self) -> bool {
        self.evidence.iotlb.used_remapped_iova
    }

    /// Returns the number of trigger mappings whose invalidation completed.
    pub const fn iotlb_completed_trigger_pages(self) -> usize {
        self.evidence.iotlb.completed_pages
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiptFacts {
    claim: BootClaimCoordinates,
    hardware: BootHardwareEvidence,
}

/// Typed VirtIO status-reset observation for one exact replayed claim.
///
/// This value is intentionally neither `Clone` nor `Copy`. It contains no
/// hardware owner and cannot activate the device. It is not a PCI FLR or a
/// domain-independent physical reset receipt.
#[must_use = "submit through the exact verifier challenge or retain for reconciliation"]
pub struct BootVirtioStatusResetReceipt {
    facts: ReceiptFacts,
}

impl BootVirtioStatusResetReceipt {
    /// Returns the exact replayed claim coordinates.
    pub const fn claim(&self) -> BootClaimCoordinates {
        self.facts.claim
    }

    /// Returns the descriptive fixed-fixture PCI coordinates.
    pub const fn device_bdf(&self) -> DeviceBdf {
        self.facts.hardware.bdf
    }

    /// Returns the dead owner's generation.
    pub const fn old_generation(&self) -> u64 {
        self.facts.claim.subject_device_generation
    }

    /// Returns the reset-domain successor generation.
    pub const fn successor_generation(&self) -> u64 {
        self.facts.hardware.observed_generation
    }

    /// Reports the exact status-zero reset observation.
    pub const fn reset_status_zero(&self) -> bool {
        self.facts.hardware.reset.reset_status_zero
    }

    /// Reports the exact PCI command readback.
    pub const fn bus_master_disabled(&self) -> bool {
        self.facts.hardware.reset.pci.bus_master_disabled
    }

    /// Reports the exact PCI INTx mask readback.
    pub const fn intx_masked(&self) -> bool {
        self.facts.hardware.reset.pci.intx_masked
    }
}

/// Typed VirtIO ISR-empty observation for one exact replayed claim.
///
/// This proves PCI INTx masking plus device ISR read-to-clear and a second
/// empty observation. It deliberately does not claim that QEMU is physical
/// hardware or that an arbitrary platform interrupt controller was drained.
#[must_use = "submit through the exact verifier challenge or retain for reconciliation"]
pub struct BootVirtioIsrEmptyReceipt {
    facts: ReceiptFacts,
}

impl BootVirtioIsrEmptyReceipt {
    /// Returns the exact replayed claim coordinates.
    pub const fn claim(&self) -> BootClaimCoordinates {
        self.facts.claim
    }

    /// Returns the descriptive fixed-fixture PCI coordinates.
    pub const fn device_bdf(&self) -> DeviceBdf {
        self.facts.hardware.bdf
    }

    /// Returns the generation established while the device remained fenced.
    pub const fn successor_generation(&self) -> u64 {
        self.facts.hardware.observed_generation
    }

    /// Returns all VirtIO ISR cause bits observed while draining.
    pub const fn observed_isr_bits(&self) -> u32 {
        self.facts.hardware.reset.observed_isr_bits
    }

    /// Returns the number of real ISR reads performed.
    pub const fn isr_reads(&self) -> usize {
        self.facts.hardware.reset.isr_reads
    }

    /// Returns the terminal consecutive empty-read count.
    pub const fn consecutive_empty_reads(&self) -> usize {
        self.facts.hardware.reset.consecutive_empty_isr_reads
    }

    /// Reports the exact PCI INTx mask readback retained through drain.
    pub const fn intx_masked(&self) -> bool {
        self.facts.hardware.reset.pci.intx_masked
    }
}

/// Typed completed global-IOTLB observation for one exact replayed claim.
///
/// The global invalidation is supplied by the audited OSTD 0.18.1 CSER patch.
/// This receipt is not sufficient to retire or reuse the replayed resource:
/// the current journal has no exact PFN/IOVA extent and this crate owns no
/// crash-persistent DMA arena. A recovery adapter must combine it with an
/// independent retained-resource custody proof.
#[must_use = "submit through the exact verifier challenge or retain for reconciliation"]
pub struct BootGlobalIotlbInvalidationReceipt {
    facts: ReceiptFacts,
}

impl BootGlobalIotlbInvalidationReceipt {
    /// Returns the exact replayed claim coordinates.
    pub const fn claim(&self) -> BootClaimCoordinates {
        self.facts.claim
    }

    /// Returns the descriptive fixed-fixture PCI coordinates.
    pub const fn device_bdf(&self) -> DeviceBdf {
        self.facts.hardware.bdf
    }

    /// Returns the dead owner's generation.
    pub const fn old_generation(&self) -> u64 {
        self.facts.claim.subject_device_generation
    }

    /// Returns the generation established after the global barrier.
    pub const fn successor_generation(&self) -> u64 {
        self.facts.hardware.observed_generation
    }

    /// Reports that the trigger page used an actual remapped IOVA.
    pub const fn used_remapped_iova(&self) -> bool {
        self.facts.hardware.iotlb.used_remapped_iova
    }

    /// Returns the number of trigger mappings whose invalidation completed.
    pub const fn completed_trigger_pages(&self) -> usize {
        self.facts.hardware.iotlb.completed_pages
    }

    /// The patched OSTD primitive submits a global, not address-selective,
    /// invalidation for this completed remapped PTE removal.
    pub const fn global_invalidation(&self) -> bool {
        true
    }

    /// OSTD 0.18.1 installs one shared second-stage table for every PCI requester.
    ///
    /// This is a pinned source contract, not an independently sampled runtime
    /// root-table identity.
    pub const fn shared_second_stage_source_contract(&self) -> bool {
        true
    }

    /// The current OSTD patch does not expose VT-d DMA read/write drain
    /// capability or descriptor-bit evidence.
    pub const fn dma_transaction_drain_observed(&self) -> bool {
        false
    }

    /// This provider cannot authorize physical page or IOVA reuse by itself.
    pub const fn resource_reuse_authorized(&self) -> bool {
        false
    }
}

/// Three heterogeneous quarantine observations bound to one exact claim.
///
/// A domain verifier may consume only the evidence kinds its claim requires.
/// The core's one-shot challenge remains the replay defense. These values do
/// not replace a crash-persistent page/IOVA custody proof.
#[must_use = "consume the typed receipts through verifier challenges"]
pub struct BootClaimQuarantineReceipts {
    reset: BootVirtioStatusResetReceipt,
    irq: BootVirtioIsrEmptyReceipt,
    iotlb: BootGlobalIotlbInvalidationReceipt,
}

impl BootClaimQuarantineReceipts {
    /// Separates the reset, IRQ-drain, and IOTLB evidence values.
    pub fn into_parts(
        self,
    ) -> (
        BootVirtioStatusResetReceipt,
        BootVirtioIsrEmptyReceipt,
        BootGlobalIotlbInvalidationReceipt,
    ) {
        (self.reset, self.irq, self.iotlb)
    }
}

struct FencedBootOwner {
    root: Root,
    masked_intx: MaskedIntx,
}

struct ResetBootOwner {
    fenced: FencedBootOwner,
    request: BootQuarantineRequest,
    pci_observation: BootPciFenceObservation,
    transport: PciTransport,
}

struct ResetCompleteBootOwner {
    fenced: FencedBootOwner,
    request: BootQuarantineRequest,
    reset: ResetDrainObservation,
}

struct PendingBootOwner {
    fenced: FencedBootOwner,
    request: BootQuarantineRequest,
    reset: ResetDrainObservation,
    iotlb: BootIotlbTombstone,
}

#[allow(dead_code)]
enum FailedBootOwner {
    Discovered(Root),
    Fenced(FencedBootOwner),
    Reset(ResetBootOwner),
    ResetComplete(ResetCompleteBootOwner),
    Iotlb(PendingBootOwner),
}

/// Physical quarantine failure.
///
/// When hardware ownership had already been acquired, this object retains it.
/// Dropping the failure never re-enables bus mastering or INTx; the installed
/// BAR registry also prevents another root from aliasing the function.
pub struct BootQuarantineFailure {
    error: BootQuarantineError,
    retained: Option<FailedBootOwner>,
}

impl BootQuarantineFailure {
    /// Returns the exact fail-closed reason.
    pub const fn error(&self) -> &BootQuarantineError {
        &self.error
    }

    /// Retries an ownership-carrying reset/ISR observation or pending IOTLB
    /// invalidation.
    ///
    /// Every other failure is returned unchanged. A terminal invalidation
    /// failure remains retained and can never produce a completed receipt.
    pub fn retry(self, poll_budget: usize) -> Result<BootQuarantineGuard, Self> {
        let Self { error, retained } = self;
        match retained {
            Some(FailedBootOwner::Reset(reset)) => {
                let reset = finish_reset(reset)?;
                begin_and_finish_iotlb(reset, poll_budget)
            }
            Some(FailedBootOwner::ResetComplete(reset)) => {
                begin_and_finish_iotlb(reset, poll_budget)
            }
            Some(FailedBootOwner::Iotlb(pending)) => finish_iotlb(pending, poll_budget),
            retained => Err(Self { error, retained }),
        }
    }
}

/// Why boot-time physical quarantine did not complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BootQuarantineError {
    PciDiscovery(PciDiscoveryError),
    PciFenceAlreadyClaimed,
    InvalidIntxRoute,
    PciFenceReadbackMismatch {
        bus_master_disabled: bool,
        intx_masked: bool,
        memory_space_enabled: bool,
        other_bits_changed: bool,
    },
    TransportClaimsUnavailable,
    Transport(VirtioPciError),
    WrongDeviceType(DeviceType),
    ResetNotAcknowledged,
    PciFenceLostAfterReset,
    IrqDrainNotConfirmed,
    IotlbAllocationFailed,
    IommuRemappingUnavailable,
    IotlbPending,
    IotlbRetainedFailure,
}

/// Linear owner which keeps the device fenced across journal replay.
///
/// Dropping this guard leaves the PCI command physically disabled and the
/// process-wide BAR registry installed. Only [`Self::try_activate`] transfers
/// the root and masked token into a production device owner.
#[must_use = "retain through replay and reconciliation, then explicitly activate"]
pub struct BootQuarantineGuard {
    fenced: FencedBootOwner,
    evidence: BootHardwareEvidence,
}

impl BootQuarantineGuard {
    /// Returns the exact fixed BDF which was physically fenced.
    pub const fn device_bdf(&self) -> DeviceBdf {
        self.evidence.bdf
    }

    /// Returns its stable portable device-scope coordinate.
    pub const fn device_scope(&self) -> BootDeviceScope {
        self.evidence.scope
    }

    /// Returns the trusted generation established while fenced.
    pub const fn observed_generation(&self) -> u64 {
        self.evidence.observed_generation
    }

    /// Snapshots the completed physical observations without releasing the
    /// quarantine owner or creating activation authority.
    pub const fn observation(&self) -> BootQuarantineObservation {
        BootQuarantineObservation {
            evidence: self.evidence,
        }
    }

    /// Binds the physical whole-device evidence to one exact replayed claim.
    ///
    /// This operation is descriptive and does not mutate hardware or release
    /// quarantine. The receiving verifier must compare every coordinate with
    /// its own core challenge.
    pub fn project_claim_quarantine(
        &self,
        claim: BootClaimCoordinates,
    ) -> Result<BootClaimQuarantineReceipts, BootReceiptBindingError> {
        build_claim_receipts(self.evidence, claim)
    }

    /// Transfers the still-fenced root into the normal production typestate.
    ///
    /// This does not enable bus mastering or unmask INTx. Those later actions
    /// still require the ordinary queue-preparation and linear INTx APIs.
    pub fn try_activate(self) -> Result<ActivatedBootDevice, BootActivationFailure> {
        let Self {
            mut fenced,
            evidence,
        } = self;
        match ProductionDevice::for_owned_device_at_generation(
            &mut fenced.root,
            evidence.observed_generation,
        ) {
            Ok(device) => Ok(ActivatedBootDevice {
                root: fenced.root,
                masked_intx: fenced.masked_intx,
                device,
            }),
            Err(error) => Err(BootActivationFailure {
                error,
                guard: Self { fenced, evidence },
            }),
        }
    }
}

/// Activation failure which returns the unchanged quarantine guard.
#[must_use = "recover the guard and keep the device quarantined"]
pub struct BootActivationFailure {
    error: ProductionDeviceClaimError,
    guard: BootQuarantineGuard,
}

impl BootActivationFailure {
    /// Returns the production-owner claim error.
    pub const fn error(&self) -> ProductionDeviceClaimError {
        self.error
    }

    /// Recovers the unchanged physical quarantine owner.
    pub fn into_guard(self) -> BootQuarantineGuard {
        self.guard
    }
}

/// Normal production owner produced only from a completed boot quarantine.
///
/// The contained INTx token remains masked and the PCI function remains unable
/// to bus-master until ordinary production preparation explicitly advances it.
#[must_use = "install or retain the complete production device owner"]
pub struct ActivatedBootDevice {
    root: Root,
    masked_intx: MaskedIntx,
    device: ProductionDevice,
}

impl ActivatedBootDevice {
    /// Returns the still-fenced BDF.
    pub const fn device_bdf(&self) -> DeviceBdf {
        self.root.device_bdf()
    }

    /// Transfers all three linear owners to the production composition root.
    ///
    /// The returned `ProductionDevice` creates only coupled transport-owner
    /// values for live requests. Those values retain the BAR owner
    /// independently of this `Root`, so dropping the root after this split
    /// cannot release or invalidate a live request's MMIO ownership.
    pub fn into_parts(self) -> (Root, MaskedIntx, ProductionDevice) {
        (self.root, self.masked_intx, self.device)
    }
}

/// Acquires and physically quarantines the fixed production VirtIO block
/// function before any journal replay.
pub fn quarantine_production_device(
    request: BootQuarantineRequest,
) -> Result<BootQuarantineGuard, BootQuarantineFailure> {
    let mut root = pci::discover_and_own_bars().map_err(|error| BootQuarantineFailure {
        error: BootQuarantineError::PciDiscovery(error),
        retained: None,
    })?;
    let (masked_intx, pci_observation) = match root.claim_boot_pci_fence() {
        Ok(fence) => fence,
        Err(error) => {
            return Err(BootQuarantineFailure {
                error: map_pci_fence_error(error),
                retained: Some(FailedBootOwner::Discovered(root)),
            });
        }
    };
    let fenced = FencedBootOwner { root, masked_intx };
    let reset = begin_reset(fenced, request, pci_observation)?;
    let reset = finish_reset(reset)?;
    begin_and_finish_iotlb(reset, IOTLB_POLL_LIMIT)
}

fn begin_reset(
    mut fenced: FencedBootOwner,
    request: BootQuarantineRequest,
    pci_observation: BootPciFenceObservation,
) -> Result<ResetBootOwner, BootQuarantineFailure> {
    let transport_owner = match pci::try_begin_transport_claims() {
        Ok(owner) => owner,
        Err(_) => {
            return Err(BootQuarantineFailure {
                error: BootQuarantineError::TransportClaimsUnavailable,
                retained: Some(FailedBootOwner::Fenced(fenced)),
            });
        }
    };
    let device_function = fenced.root.device_function();
    let transport = RawPciTransport::new::<OstdHal, _>(fenced.root.raw_mut(), device_function)
        .map(|transport| PciTransport::new(transport, transport_owner));
    let transport = match transport {
        Ok(transport) => transport,
        Err(error) => {
            return Err(BootQuarantineFailure {
                error: BootQuarantineError::Transport(error),
                retained: Some(FailedBootOwner::Fenced(fenced)),
            });
        }
    };
    Ok(ResetBootOwner {
        fenced,
        request,
        pci_observation,
        transport,
    })
}

fn finish_reset(
    mut owner: ResetBootOwner,
) -> Result<ResetCompleteBootOwner, BootQuarantineFailure> {
    let result = reset_and_drain_transport(
        &mut owner.fenced.root,
        &mut owner.transport,
        owner.pci_observation,
    );
    let reset = match result {
        Ok(reset) => reset,
        Err(error) => {
            return Err(BootQuarantineFailure {
                error,
                retained: Some(FailedBootOwner::Reset(owner)),
            });
        }
    };
    drop(owner.transport);
    Ok(ResetCompleteBootOwner {
        fenced: owner.fenced,
        request: owner.request,
        reset,
    })
}

fn reset_and_drain_transport(
    root: &mut Root,
    transport: &mut PciTransport,
    pci_observation: BootPciFenceObservation,
) -> Result<ResetDrainObservation, BootQuarantineError> {
    if transport.device_type() != DeviceType::Block {
        return Err(BootQuarantineError::WrongDeviceType(
            transport.device_type(),
        ));
    }

    transport.set_status(DeviceStatus::empty());
    let mut reset_status_zero = false;
    for _ in 0..RESET_POLL_LIMIT {
        if transport.get_status() == DeviceStatus::empty() {
            reset_status_zero = true;
            break;
        }
        spin_loop();
    }
    if !reset_status_zero {
        return Err(BootQuarantineError::ResetNotAcknowledged);
    }
    if !root.boot_pci_fence_is_exact() {
        return Err(BootQuarantineError::PciFenceLostAfterReset);
    }

    let mut observed_isr_bits = 0u32;
    let mut isr_reads = 0usize;
    let mut consecutive_empty_isr_reads = 0usize;
    for _ in 0..IRQ_DRAIN_POLL_LIMIT {
        let status = transport.ack_interrupt();
        observed_isr_bits |= status.bits();
        isr_reads += 1;
        if status == InterruptStatus::empty() {
            consecutive_empty_isr_reads += 1;
            if consecutive_empty_isr_reads == REQUIRED_EMPTY_ISR_OBSERVATIONS {
                break;
            }
        } else {
            consecutive_empty_isr_reads = 0;
        }
        spin_loop();
    }
    if consecutive_empty_isr_reads != REQUIRED_EMPTY_ISR_OBSERVATIONS
        || !root.boot_pci_fence_is_exact()
    {
        return Err(BootQuarantineError::IrqDrainNotConfirmed);
    }

    Ok(ResetDrainObservation {
        pci: pci_observation,
        reset_status_zero,
        observed_isr_bits,
        isr_reads,
        consecutive_empty_isr_reads,
    })
}

fn begin_and_finish_iotlb(
    reset: ResetCompleteBootOwner,
    poll_budget: usize,
) -> Result<BootQuarantineGuard, BootQuarantineFailure> {
    let iotlb = match dma::begin_boot_iotlb_barrier() {
        Ok(iotlb) => iotlb,
        Err(error) => {
            return Err(BootQuarantineFailure {
                error: match error {
                    BootIotlbStartError::AllocationFailed => {
                        BootQuarantineError::IotlbAllocationFailed
                    }
                    BootIotlbStartError::RemappingUnavailable => {
                        BootQuarantineError::IommuRemappingUnavailable
                    }
                },
                retained: Some(FailedBootOwner::ResetComplete(reset)),
            });
        }
    };
    finish_iotlb(
        PendingBootOwner {
            fenced: reset.fenced,
            request: reset.request,
            reset: reset.reset,
            iotlb,
        },
        poll_budget,
    )
}

fn finish_iotlb(
    pending: PendingBootOwner,
    poll_budget: usize,
) -> Result<BootQuarantineGuard, BootQuarantineFailure> {
    let PendingBootOwner {
        fenced,
        request,
        reset,
        iotlb,
    } = pending;
    match iotlb.retry(poll_budget) {
        BootIotlbProgress::Complete(iotlb) => {
            let bdf = fenced.root.device_bdf();
            Ok(BootQuarantineGuard {
                fenced,
                evidence: BootHardwareEvidence {
                    bdf,
                    scope: BootDeviceScope::from_bdf(bdf),
                    observed_generation: request.observed_generation,
                    reset,
                    iotlb,
                },
            })
        }
        BootIotlbProgress::Pending(iotlb) => Err(BootQuarantineFailure {
            error: BootQuarantineError::IotlbPending,
            retained: Some(FailedBootOwner::Iotlb(PendingBootOwner {
                fenced,
                request,
                reset,
                iotlb,
            })),
        }),
        BootIotlbProgress::RetainedFailure(iotlb) => Err(BootQuarantineFailure {
            error: BootQuarantineError::IotlbRetainedFailure,
            retained: Some(FailedBootOwner::Iotlb(PendingBootOwner {
                fenced,
                request,
                reset,
                iotlb,
            })),
        }),
    }
}

fn map_pci_fence_error(error: BootPciFenceError) -> BootQuarantineError {
    match error {
        BootPciFenceError::AlreadyClaimed => BootQuarantineError::PciFenceAlreadyClaimed,
        BootPciFenceError::InvalidRoute => BootQuarantineError::InvalidIntxRoute,
        BootPciFenceError::CommandReadbackMismatch {
            bus_master_disabled,
            intx_masked,
            memory_space_enabled,
            other_bits_changed,
        } => BootQuarantineError::PciFenceReadbackMismatch {
            bus_master_disabled,
            intx_masked,
            memory_space_enabled,
            other_bits_changed,
        },
    }
}

fn build_claim_receipts(
    evidence: BootHardwareEvidence,
    claim: BootClaimCoordinates,
) -> Result<BootClaimQuarantineReceipts, BootReceiptBindingError> {
    if claim.scope != evidence.scope {
        return Err(BootReceiptBindingError::ForeignDeviceScope {
            expected: evidence.scope,
            observed: claim.scope,
        });
    }
    if claim.subject_device_generation >= evidence.observed_generation {
        return Err(BootReceiptBindingError::NonOlderGeneration {
            subject: claim.subject_device_generation,
            observed_boot_generation: evidence.observed_generation,
        });
    }
    let facts = ReceiptFacts {
        claim,
        hardware: evidence,
    };
    Ok(BootClaimQuarantineReceipts {
        reset: BootVirtioStatusResetReceipt { facts },
        irq: BootVirtioIsrEmptyReceipt { facts },
        iotlb: BootGlobalIotlbInvalidationReceipt { facts },
    })
}

#[cfg(any(test, ktest))]
mod tests {
    use super::*;
    #[cfg(ktest)]
    use ostd::prelude::*;

    const SOURCE: &str = include_str!("boot_quarantine.rs");
    const BDF: DeviceBdf = DeviceBdf::from_coordinates(0, 5, 0);

    const fn evidence(generation: u64) -> BootHardwareEvidence {
        BootHardwareEvidence {
            bdf: BDF,
            scope: BootDeviceScope::from_bdf(BDF),
            observed_generation: generation,
            reset: ResetDrainObservation {
                pci: BootPciFenceObservation {
                    bus_master_disabled: true,
                    intx_masked: true,
                    memory_space_enabled: true,
                },
                reset_status_zero: true,
                observed_isr_bits: 3,
                isr_reads: 4,
                consecutive_empty_isr_reads: 2,
            },
            iotlb: BootIotlbObservation {
                completed_pages: 1,
                used_remapped_iova: true,
            },
        }
    }

    fn claim(scope: BootDeviceScope, generation: u64) -> BootClaimCoordinates {
        BootClaimCoordinates::new(scope, 1, 2, 3, 4, 5, 6, 7, generation)
            .expect("test coordinates are non-zero")
    }

    #[cfg_attr(test, test)]
    #[cfg_attr(ktest, ktest)]
    fn fixed_bdf_maps_to_stable_portable_scope() {
        assert_eq!(BootDeviceScope::from_bdf(BDF).get(), 0x501);
    }

    #[cfg_attr(test, test)]
    #[cfg_attr(ktest, ktest)]
    fn claim_coordinates_reject_every_reserved_zero() {
        assert_eq!(
            BootDeviceScope::new(0),
            Err(BootClaimCoordinateError::Zero(
                BootClaimCoordinateField::DeviceScope
            ))
        );
        let scope = BootDeviceScope::new(1).unwrap();
        let inputs = [
            (0, 2, 3, 4, 5, 6, 7, 8),
            (1, 0, 3, 4, 5, 6, 7, 8),
            (1, 2, 0, 4, 5, 6, 7, 8),
            (1, 2, 3, 0, 5, 6, 7, 8),
            (1, 2, 3, 4, 0, 6, 7, 8),
            (1, 2, 3, 4, 5, 0, 7, 8),
            (1, 2, 3, 4, 5, 6, 0, 8),
            (1, 2, 3, 4, 5, 6, 7, 0),
        ];
        for (root, sequence, claim, kind, resource, resource_generation, units, generation) in
            inputs
        {
            assert!(
                BootClaimCoordinates::new(
                    scope,
                    root,
                    sequence,
                    claim,
                    kind,
                    resource,
                    resource_generation,
                    units,
                    generation,
                )
                .is_err()
            );
        }
    }

    #[cfg_attr(test, test)]
    #[cfg_attr(ktest, ktest)]
    fn receipts_bind_scope_resource_and_older_generation() {
        let hardware = evidence(9);
        let coordinates = claim(hardware.scope, 8);
        let receipts = build_claim_receipts(hardware, coordinates).expect("older generation binds");
        let (reset, irq, iotlb) = receipts.into_parts();

        assert_eq!(reset.claim(), coordinates);
        assert_eq!(reset.device_bdf(), BDF);
        assert_eq!(reset.old_generation(), 8);
        assert_eq!(reset.successor_generation(), 9);
        assert!(reset.reset_status_zero());
        assert!(reset.bus_master_disabled());
        assert!(reset.intx_masked());

        assert_eq!(irq.claim(), coordinates);
        assert_eq!(irq.observed_isr_bits(), 3);
        assert_eq!(irq.isr_reads(), 4);
        assert_eq!(irq.consecutive_empty_reads(), 2);
        assert!(irq.intx_masked());

        assert_eq!(iotlb.claim(), coordinates);
        assert_eq!(iotlb.old_generation(), 8);
        assert_eq!(iotlb.successor_generation(), 9);
        assert!(iotlb.used_remapped_iova());
        assert_eq!(iotlb.completed_trigger_pages(), 1);
        assert!(iotlb.global_invalidation());
        assert!(iotlb.shared_second_stage_source_contract());
        assert!(!iotlb.dma_transaction_drain_observed());
        assert!(!iotlb.resource_reuse_authorized());
    }

    #[cfg_attr(test, test)]
    #[cfg_attr(ktest, ktest)]
    fn receipt_binding_accepts_repeated_recovery_and_rejects_non_older_generation() {
        let hardware = evidence(9);
        let foreign = BootDeviceScope::new(hardware.scope.get() + 1).unwrap();
        assert!(matches!(
            build_claim_receipts(hardware, claim(foreign, 8)),
            Err(BootReceiptBindingError::ForeignDeviceScope { .. })
        ));
        build_claim_receipts(hardware, claim(hardware.scope, 7))
            .expect("a tombstone may survive multiple recovery checkpoints");
        assert_eq!(
            build_claim_receipts(hardware, claim(hardware.scope, 9))
                .err()
                .expect("equal generation rejected"),
            BootReceiptBindingError::NonOlderGeneration {
                subject: 9,
                observed_boot_generation: 9,
            }
        );
        assert!(matches!(
            build_claim_receipts(hardware, claim(hardware.scope, 10)),
            Err(BootReceiptBindingError::NonOlderGeneration { .. })
        ));
    }

    #[cfg_attr(test, test)]
    #[cfg_attr(ktest, ktest)]
    fn source_keeps_physical_actions_and_receipts_on_separate_sides() {
        let implementation = SOURCE
            .split_once("#[cfg(any(test, ktest))]")
            .expect("test module follows implementation")
            .0;
        assert!(implementation.contains("claim_boot_pci_fence()"));
        assert!(implementation.contains("transport.set_status(DeviceStatus::empty())"));
        assert!(implementation.contains("transport.ack_interrupt()"));
        assert!(implementation.contains("dma::begin_boot_iotlb_barrier()"));
        assert!(implementation.contains("ProductionDevice::for_owned_device"));
        assert!(!implementation.contains("impl Clone for BootVirtioStatusResetReceipt"));
        assert!(!implementation.contains("impl Clone for BootVirtioIsrEmptyReceipt"));
        assert!(!implementation.contains("impl Clone for BootGlobalIotlbInvalidationReceipt"));
        assert!(!implementation.contains("pub unsafe"));
    }

    #[cfg_attr(test, test)]
    #[cfg_attr(ktest, ktest)]
    fn activation_uses_transport_owner_coupling_before_live_requests() {
        let implementation = SOURCE
            .split_once("#[cfg(any(test, ktest))]")
            .expect("test module follows implementation")
            .0;
        assert!(implementation.contains("OwnedPciTransport"));
        let claim = implementation
            .find("let transport_owner = match pci::try_begin_transport_claims()")
            .expect("activation reset claims a linear transport owner");
        let construct = implementation
            .find("PciTransport::new(transport, transport_owner)")
            .expect("raw transport is coupled to the owner");
        assert!(claim < construct);
        assert!(!implementation.contains("release_unexposed_transport_claims_checked"));
    }
}
