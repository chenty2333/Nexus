// SPDX-License-Identifier: MPL-2.0

//! The CSER arm of the queryable-tool plus DMA experiment.
//!
//! This module deliberately owns the *semantic* experiment sequence, not a
//! second persistence or device implementation.  Its caller supplies a
//! recovered [`OstdCserRuntime`] or [`QuarantinedRecoveredBoot`] backed by the
//! experiment ATA/TPM provider and real DMA operations built from
//! `core_dma_adapter`.  In particular, an
//! in-memory journal is not an implementation of this arm.
//!
//! The two component commit intents are made durable together before either
//! the UART endpoint may receive `POST` or the VirtIO queue may be published.
//! The tool and DMA components subsequently close independently: a recovered
//! tool outcome cannot release a device claim, and reset/IRQ/IOTLB evidence
//! cannot settle the tool's logical outcome.

use cser_core::{
    ChargeAccountId, ClaimId, ClaimScope, Command, CommandRequest, CommitIntent,
    ComponentCommitOperation, ComponentProjection, CompositeEffectProjection,
    CoordinatedPersistenceError, CoreError, CoreLimits, DEVICE_CLAIM_IOVA,
    DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT, DeviceScopeId, Digest, EffectEscapeState,
    EffectId, Freshness, PrincipalIncarnation, ResourceGeneration, ResourceId, RetirementState,
    SettlementState, TOOL_CLAIM_OUTCOME_SLOT, TOOL_DMA_COMPONENT_DMA, TOOL_DMA_COMPONENT_TOOL,
    TOOL_DMA_OPERATION_COMPOSITE, TransitionDurability, TransitionOutput, TransitionReceipt,
    TrustedAnchorBackend, TxError, tool_dma_catalog,
};

use super::{
    core_reboot::{BootDeviceQuarantineGuard, OstdBootJournal, QuarantinedRecoveredBoot},
    core_runtime::OstdCserRuntime,
    core_tool_adapter::{DurableToolObservation, ToolEndpoint, ToolOperationPlan},
    core_tool_dma_runtime::ToolDmaRuntime,
};

/// The one semantic authority used by both a live runtime and a recovered,
/// still-quarantined boot.  The experiment never stores an `ArmedToolDma`
/// across a reboot: a successor must inspect this owner again and obtain only
/// the outstanding intents reconstructed by the engine.
pub(crate) trait ToolDmaCoreOwner {
    type PersistenceError;

    fn observe<R>(&self, operation: impl FnOnce(&cser_core::Engine) -> R) -> R;

    fn transact(
        &mut self,
        command: Command,
    ) -> Result<TransitionReceipt, TxError<Self::PersistenceError>>;
}

impl<P: TransitionDurability> ToolDmaCoreOwner for OstdCserRuntime<P> {
    type PersistenceError = P::Error;

    fn observe<R>(&self, operation: impl FnOnce(&cser_core::Engine) -> R) -> R {
        OstdCserRuntime::observe(self, operation)
    }

    fn transact(
        &mut self,
        command: Command,
    ) -> Result<TransitionReceipt, TxError<Self::PersistenceError>> {
        OstdCserRuntime::transact(self, command)
    }
}

impl<J, A, G> ToolDmaCoreOwner for QuarantinedRecoveredBoot<J, A, G>
where
    J: OstdBootJournal,
    A: TrustedAnchorBackend,
    G: BootDeviceQuarantineGuard,
{
    type PersistenceError = CoordinatedPersistenceError<J::Error, A::Error>;

    fn observe<R>(&self, operation: impl FnOnce(&cser_core::Engine) -> R) -> R {
        QuarantinedRecoveredBoot::observe(self, operation)
    }

    fn transact(
        &mut self,
        command: Command,
    ) -> Result<TransitionReceipt, TxError<Self::PersistenceError>> {
        QuarantinedRecoveredBoot::recovery_transact(self, command)
    }
}

/// The seven externally visible, ordered crash positions of the CSER arm.
///
/// Every position describes an already-durable semantic fact or a completed
/// external endpoint/device action.  A UART barrier is only an observation;
/// it never upgrades the preceding step's durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u16)]
pub(crate) enum ToolDmaBarrier {
    /// The composite topology and every claim are durably prepared.
    TopologyPrepared = 1,
    /// Tool and DMA write-ahead commit intents are durably co-recorded.
    CommitIntentsDurable = 2,
    /// The endpoint has durably applied POST; its reply may now be lost.
    ToolEndpointApplied = 3,
    /// The real VirtIO publication has become device-visible and its exact
    /// local commit acknowledgement is durable.  The acknowledgement belongs
    /// before the crash marker because a killed QEMU cannot reconstruct a
    /// transient publication receipt from `avail.idx` alone.
    DmaQueuePublished = 4,
    /// The tool component's commit acknowledgement is durable.
    ToolCommitAcknowledged = 5,
    /// The tool component's reconciliation intent is durable. On first boot
    /// this follows the POST observation; after a crash the successor GETs
    /// first and reaches this state only through a recovered settlement claim.
    ToolApplyIntentDurable = 6,
    /// Independent tool outcome and DMA quiescence retirements are durable.
    ComponentsRetired = 7,
}

impl ToolDmaBarrier {
    pub(crate) const ALL: [Self; 7] = [
        Self::TopologyPrepared,
        Self::CommitIntentsDurable,
        Self::ToolEndpointApplied,
        Self::DmaQueuePublished,
        Self::ToolCommitAcknowledged,
        Self::ToolApplyIntentDurable,
        Self::ComponentsRetired,
    ];

    pub(crate) const fn wire_id(self) -> u16 {
        self as u16
    }
}

/// A host-facing hook.  The QEMU arm implements this with `CrashProbe`; pure
/// tests may merely record the sequence.  Returning an error always retains
/// the core/device authority held by the caller and is not treated as success.
pub(crate) trait ToolDmaBarrierHook {
    type Error;

    fn reached(&mut self, barrier: ToolDmaBarrier) -> Result<(), Self::Error>;
}

/// Exact catalog-bound coordinates for one experimental composite effect.
///
/// Keeping the identities in one value makes accidental mixing with the
/// standard reply/DMA profile mechanically awkward.  The resource identifiers
/// are opaque CSER coordinates; hardware aliasing remains the VirtIO/IOMMU
/// gate's responsibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolDmaCoordinates {
    effect: EffectId,
    actor: PrincipalIncarnation,
    binding_generation: u64,
    account: ChargeAccountId,
    tool_claim: ClaimId,
    tool_resource: ResourceId,
    tool_generation: ResourceGeneration,
    queue_claim: ClaimId,
    queue_resource: ResourceId,
    page_claim: ClaimId,
    page_resource: ResourceId,
    iova_claim: ClaimId,
    iova_resource: ResourceId,
    device_scope: DeviceScopeId,
    device_generation: ResourceGeneration,
}

impl ToolDmaCoordinates {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        effect: EffectId,
        actor: PrincipalIncarnation,
        binding_generation: u64,
        account: ChargeAccountId,
        tool_claim: ClaimId,
        tool_resource: ResourceId,
        tool_generation: ResourceGeneration,
        queue_claim: ClaimId,
        queue_resource: ResourceId,
        page_claim: ClaimId,
        page_resource: ResourceId,
        iova_claim: ClaimId,
        iova_resource: ResourceId,
        device_scope: DeviceScopeId,
        device_generation: ResourceGeneration,
    ) -> Option<Self> {
        if binding_generation == 0
            || tool_claim.get() == queue_claim.get()
            || tool_claim.get() == page_claim.get()
            || tool_claim.get() == iova_claim.get()
            || queue_claim.get() == page_claim.get()
            || queue_claim.get() == iova_claim.get()
            || page_claim.get() == iova_claim.get()
            || tool_resource.get() == queue_resource.get()
            || tool_resource.get() == page_resource.get()
            || tool_resource.get() == iova_resource.get()
            || queue_resource.get() == page_resource.get()
            || queue_resource.get() == iova_resource.get()
            || page_resource.get() == iova_resource.get()
        {
            return None;
        }
        Some(Self {
            effect,
            actor,
            binding_generation,
            account,
            tool_claim,
            tool_resource,
            tool_generation,
            queue_claim,
            queue_resource,
            page_claim,
            page_resource,
            iova_claim,
            iova_resource,
            device_scope,
            device_generation,
        })
    }

    pub(crate) const fn effect(self) -> EffectId {
        self.effect
    }
    pub(crate) const fn actor(self) -> PrincipalIncarnation {
        self.actor
    }
    pub(crate) const fn binding_generation(self) -> u64 {
        self.binding_generation
    }

    fn tool_plan(self, run_id: [u8; 16], payload: &[u8]) -> Result<ToolOperationPlan, CoreError> {
        ToolOperationPlan::new(
            run_id,
            self.effect,
            TOOL_DMA_COMPONENT_TOOL,
            self.tool_claim,
            self.tool_resource,
            self.tool_generation,
            payload,
        )
        .map_err(|_| CoreError::InvalidPayload)
    }

    fn topology(self) -> [CommandRequest; 5] {
        [
            CommandRequest::CreateCompositeEffect {
                effect: self.effect,
                origin: self.actor,
                binding_generation: self.binding_generation,
                kind: TOOL_DMA_OPERATION_COMPOSITE,
                charge_account: self.account,
            },
            CommandRequest::AddComponentClaim {
                effect: self.effect,
                component: TOOL_DMA_COMPONENT_TOOL,
                actor: self.actor,
                binding_generation: self.binding_generation,
                claim: self.tool_claim,
                kind: TOOL_CLAIM_OUTCOME_SLOT,
                scope: ClaimScope::Logical,
                resource: self.tool_resource,
                resource_generation: self.tool_generation,
                units: 1,
            },
            CommandRequest::AddComponentClaim {
                effect: self.effect,
                component: TOOL_DMA_COMPONENT_DMA,
                actor: self.actor,
                binding_generation: self.binding_generation,
                claim: self.queue_claim,
                kind: DEVICE_CLAIM_QUEUE_SLOT,
                scope: ClaimScope::Device(self.device_scope),
                resource: self.queue_resource,
                resource_generation: self.device_generation,
                units: 1,
            },
            CommandRequest::AddComponentClaim {
                effect: self.effect,
                component: TOOL_DMA_COMPONENT_DMA,
                actor: self.actor,
                binding_generation: self.binding_generation,
                claim: self.page_claim,
                kind: DEVICE_CLAIM_PINNED_PAGE,
                scope: ClaimScope::Device(self.device_scope),
                resource: self.page_resource,
                resource_generation: self.device_generation,
                // The QEMU experiment's persistent DMA arena is exactly
                // three pages.  This must agree with the real IOTLB closure
                // receipt; recording one here would make a later recovery
                // verifier reject the claim rather than silently resize it.
                units: 3,
            },
            CommandRequest::AddComponentClaim {
                effect: self.effect,
                component: TOOL_DMA_COMPONENT_DMA,
                actor: self.actor,
                binding_generation: self.binding_generation,
                claim: self.iova_claim,
                kind: DEVICE_CLAIM_IOVA,
                scope: ClaimScope::Device(self.device_scope),
                resource: self.iova_resource,
                resource_generation: self.device_generation,
                units: 3,
            },
        ]
    }
}

/// The only construction path for the experiment's semantic ledger.
///
/// It deliberately does not call `standard_catalog`.  The caller must supply
/// a real durability provider; the returned runtime is not a boot/recovery
/// authority until the experiment ATA/TPM recovery layer has selected and
/// authenticated its journal prefix.
pub(crate) fn new_tool_dma_runtime<P>(persistence: P, freshness: Freshness) -> OstdCserRuntime<P> {
    OstdCserRuntime::from_engine(
        cser_core::Engine::new(tool_dma_catalog(), CoreLimits::bounded_default(), freshness),
        persistence,
    )
}

/// Error returned before any caller-owned hardware authority is consumed.
#[derive(Debug)]
pub(crate) enum ToolDmaExperimentError<E, B = ()> {
    Transition(TxError<E>),
    Barrier(B),
    Core(CoreError),
    UnexpectedTransitionOutput,
    MissingToolIntent,
    MissingDmaIntent,
}

/// One cross-component measurement point emitted by the experiment runner.
///
/// `tool_retained_claims` and `dma_retained_claims` are deliberately separate:
/// their difference is the bounded experiment's direct measure of partial
/// discharge rather than an inferred throughput number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolDmaMetrics {
    pub(crate) revision: u64,
    pub(crate) retired_components: usize,
    pub(crate) reconciliation_steps: usize,
    pub(crate) retained_claims: usize,
    pub(crate) tool_retained_claims: usize,
    pub(crate) dma_retained_claims: usize,
    pub(crate) projection: Digest,
}

pub(crate) fn tool_dma_metrics<O: ToolDmaCoreOwner>(
    runtime: &O,
    effect: EffectId,
) -> ToolDmaMetrics {
    runtime.observe(|engine| {
        let retained = engine.retained_component_claims();
        let tool = engine
            .component(effect, TOOL_DMA_COMPONENT_TOOL)
            .expect("tool-DMA metrics require the sealed tool component");
        let dma = engine
            .component(effect, TOOL_DMA_COMPONENT_DMA)
            .expect("tool-DMA metrics require the sealed DMA component");
        let mut tool_retained_claims = 0;
        let mut dma_retained_claims = 0;
        for claim in retained.into_iter().filter(|claim| claim.effect == effect) {
            match claim.component {
                TOOL_DMA_COMPONENT_TOOL => tool_retained_claims += 1,
                TOOL_DMA_COMPONENT_DMA => dma_retained_claims += 1,
                _ => {}
            }
        }
        ToolDmaMetrics {
            revision: engine.revision(),
            retired_components: [tool, dma]
                .into_iter()
                .filter(|component| {
                    matches!(
                        component.retirement,
                        RetirementState::Retired | RetirementState::Released
                    )
                })
                .count(),
            reconciliation_steps: usize::from(matches!(tool.settlement, SettlementState::Settled)),
            retained_claims: tool_retained_claims + dma_retained_claims,
            tool_retained_claims,
            dma_retained_claims,
            projection: engine.projection_digest(),
        }
    })
}

/// A postcondition suitable for the final matrix receipt.  It intentionally
/// makes no claim about a device's physical drain: it says only that the core
/// has no remaining claim in this composite after independently verified
/// endpoint outcome and device-quiescence facts were accepted.
pub(crate) fn tool_dma_terminal(metrics: ToolDmaMetrics) -> bool {
    metrics.retired_components == 2
        && metrics.reconciliation_steps == 1
        && metrics.retained_claims == 0
        && metrics.tool_retained_claims == 0
        && metrics.dma_retained_claims == 0
}

/// Durably armed composite effect.  Both returned commit intents come from
/// one `RecordCompositeCommitIntents` transition and therefore share the same
/// parent `EffectId`, actor, and frozen catalog identity.
#[derive(Debug)]
pub(crate) struct ArmedToolDma {
    coordinates: ToolDmaCoordinates,
    tool: ToolDmaRuntime,
    tool_intent: Option<CommitIntent>,
    dma_intent: Option<CommitIntent>,
}

impl ArmedToolDma {
    pub(crate) const fn effect(&self) -> EffectId {
        self.coordinates.effect
    }
    pub(crate) const fn tool_plan(&self) -> ToolOperationPlan {
        self.tool.plan()
    }
    /// Transfers the independent DMA commit authority without consuming the
    /// tool plan or its still-outstanding intent.  This is needed because a
    /// real queue publication and the endpoint POST are deliberately allowed
    /// to escape in either order after their intents were co-recorded.
    pub(crate) fn take_dma_intent(&mut self) -> Result<CommitIntent, CoreError> {
        self.dma_intent.take().ok_or(CoreError::StaleCommitIntent)
    }

    /// Calls POST only after the exact tool operation key and payload digest
    /// are represented by a durable component commit intent.  A transport
    /// reply is returned for later verification; it has not retired any claim.
    pub(crate) fn post_tool<E: ToolEndpoint>(
        &self,
        endpoint: &mut E,
    ) -> Result<DurableToolObservation, E::Error> {
        self.tool.submit(endpoint)
    }

    /// The lost-reply recovery path.  It always begins with GET and uses the
    /// same immutable operation key/payload digest as the original POST.
    pub(crate) fn recover_tool<E: ToolEndpoint>(
        &self,
        endpoint: &mut E,
    ) -> Result<DurableToolObservation, E::Error> {
        self.tool.recover(endpoint)
    }

    /// Records the endpoint outcome as a component-local commit fact.  This
    /// neither settles nor retires the component, and has no DMA authority.
    pub(crate) fn acknowledge_tool_commit<O: ToolDmaCoreOwner>(
        &mut self,
        runtime: &mut O,
        observation: &DurableToolObservation,
    ) -> Result<(), ToolDmaExperimentError<O::PersistenceError>> {
        let intent = self
            .tool_intent
            .take()
            .ok_or(ToolDmaExperimentError::Core(CoreError::StaleCommitIntent))?;
        let command = match runtime
            .observe(|engine| self.tool.acknowledge_commit(engine, intent, observation))
        {
            Ok(command) => command,
            Err(failure) => {
                let error = failure.error().clone();
                self.tool_intent = Some(failure.into_intent());
                return Err(ToolDmaExperimentError::Core(error));
            }
        };
        expect_none(runtime.transact(command))
    }
}

/// Creates the composite topology, freezes it, and atomically writes both
/// component commit intents.  `dma_arena_digest` must name the exact durable
/// persistent-DMA-arena layout, not a transient VirtIO preparation receipt:
/// boot IOTLB verification binds recovery to that arena coordinate.  It is
/// accepted as a digest here so this semantic module never fabricates hardware
/// authority.
pub(crate) fn arm_tool_dma<O: ToolDmaCoreOwner, H: ToolDmaBarrierHook>(
    runtime: &mut O,
    coordinates: ToolDmaCoordinates,
    run_id: [u8; 16],
    payload: &[u8],
    dma_arena_digest: Digest,
    barriers: &mut H,
) -> Result<ArmedToolDma, ToolDmaExperimentError<O::PersistenceError, H::Error>> {
    let plan = coordinates
        .tool_plan(run_id, payload)
        .map_err(ToolDmaExperimentError::Core)?;
    for command in coordinates.topology() {
        expect_none(runtime.transact(command.into()))?;
    }
    expect_none(
        runtime.transact(
            CommandRequest::PrepareCompositeEffect {
                effect: coordinates.effect,
                actor: coordinates.actor,
                binding_generation: coordinates.binding_generation,
            }
            .into(),
        ),
    )?;
    barriers
        .reached(ToolDmaBarrier::TopologyPrepared)
        .map_err(ToolDmaExperimentError::Barrier)?;

    let receipt =
        runtime
            .transact(
                CommandRequest::RecordCompositeCommitIntents {
                    effect: coordinates.effect,
                    actor: coordinates.actor,
                    binding_generation: coordinates.binding_generation,
                    operations: alloc::vec![
                        ComponentCommitOperation::new(
                            TOOL_DMA_COMPONENT_TOOL,
                            plan.operation_digest(),
                        ),
                        ComponentCommitOperation::new(TOOL_DMA_COMPONENT_DMA, dma_arena_digest),
                    ],
                }
                .into(),
            )
            .map_err(ToolDmaExperimentError::Transition)?;
    let (tool_intent, dma_intent) = split_intents(receipt.into_output())?;
    barriers
        .reached(ToolDmaBarrier::CommitIntentsDurable)
        .map_err(ToolDmaExperimentError::Barrier)?;
    let tool = ToolDmaRuntime::new(plan, 1)
        .ok_or(ToolDmaExperimentError::Core(CoreError::InvalidPayload))?;
    Ok(ArmedToolDma {
        coordinates,
        tool,
        tool_intent: Some(tool_intent),
        dma_intent: Some(dma_intent),
    })
}

/// Recovery classification derived solely from the replayed core projection.
///
/// It deliberately does not infer whether a queue publication escaped: that is
/// a provider question answered only while the recovered boot retains its
/// quarantine guard.  The classification says which *durable core facts* a
/// successor has, and exposes reconstructed one-shot commit intents only when
/// the engine still reports them as outstanding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolDmaResumeState {
    /// No composite with this effect identity was recovered.
    Absent,
    /// The two-component topology is prepared but has no durable external
    /// commit cohort.
    Prepared,
    /// At least one exact component commit intent remains outstanding.
    OutstandingCommits { tool: bool, dma: bool },
    /// No commit intent remains, but one or more component claims remain.
    /// A successor must obtain the appropriate outcome or quiescence evidence
    /// before it can advance either component.
    Retained,
    /// The replayed effect has no retained claims and is terminal.
    Terminal,
}

/// One reconstructed experiment state.  This is intentionally not an
/// `ArmedToolDma`: it contains no endpoint plan or device authority from the
/// previous process.  Its commit intents are freshly reconstructed from the
/// replayed engine and remain linear.
#[derive(Debug)]
pub(crate) struct ToolDmaResume {
    state: ToolDmaResumeState,
    parent: Option<CompositeEffectProjection>,
    tool: Option<ComponentProjection>,
    dma: Option<ComponentProjection>,
    tool_intent: Option<CommitIntent>,
    dma_intent: Option<CommitIntent>,
}

impl ToolDmaResume {
    pub(crate) const fn state(&self) -> ToolDmaResumeState {
        self.state
    }

    pub(crate) const fn parent(&self) -> Option<CompositeEffectProjection> {
        self.parent
    }

    pub(crate) const fn tool(&self) -> Option<ComponentProjection> {
        self.tool
    }

    pub(crate) const fn dma(&self) -> Option<ComponentProjection> {
        self.dma
    }

    /// Reports the narrow post-checkpoint authority for retrying an absent
    /// tool operation under the same idempotency key. Boot recovery has
    /// already consumed the process-local `CommitIntent`; the durable
    /// replacement is the exact operation digest preserved as both the
    /// committed coordinate and its indeterminate outcome reason.
    pub(crate) fn allows_tool_idempotent_retry(&self, operation: Digest) -> bool {
        self.state == ToolDmaResumeState::Retained
            && self.tool.is_some_and(|tool| {
                tool.commit == cser_core::CommitState::Committed
                    && tool.commit_operation == Some(operation)
                    && tool.outcome == cser_core::OutcomeState::Indeterminate(operation)
                    && tool.retained_claims > 0
            })
    }

    /// Consumes only the reconstructed, still-outstanding authorities.  A
    /// caller cannot receive a commit intent once the projection shows that it
    /// was acknowledged before the crash.
    pub(crate) fn into_outstanding_intents(self) -> (Option<CommitIntent>, Option<CommitIntent>) {
        (self.tool_intent, self.dma_intent)
    }
}

/// A recovered projection is not the topology this experiment owns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ToolDmaResumeError {
    Core(CoreError),
    WrongCompositeKind,
    WrongComponentCount,
    MissingComponent,
    UnexpectedCommitIntent,
    ImpossibleProjection,
}

/// Reconstructs the experiment's resume state from the authoritative core.
///
/// This is the sole cross-boot entry point.  In particular, callers must not
/// retain or deserialize [`ArmedToolDma`]; doing so would incorrectly treat a
/// pre-crash process-local endpoint plan or device receipt as recovery
/// authority.
pub(crate) fn resume_tool_dma<O: ToolDmaCoreOwner>(
    runtime: &O,
    effect: EffectId,
) -> Result<ToolDmaResume, ToolDmaResumeError> {
    runtime.observe(|engine| {
        let Some(parent) = engine.composite_effect(effect) else {
            return Ok(ToolDmaResume {
                state: ToolDmaResumeState::Absent,
                parent: None,
                tool: None,
                dma: None,
                tool_intent: None,
                dma_intent: None,
            });
        };
        if parent.kind != TOOL_DMA_OPERATION_COMPOSITE {
            return Err(ToolDmaResumeError::WrongCompositeKind);
        }
        if parent.component_count != 2 {
            return Err(ToolDmaResumeError::WrongComponentCount);
        }
        let tool = engine
            .component(effect, TOOL_DMA_COMPONENT_TOOL)
            .ok_or(ToolDmaResumeError::MissingComponent)?;
        let dma = engine
            .component(effect, TOOL_DMA_COMPONENT_DMA)
            .ok_or(ToolDmaResumeError::MissingComponent)?;

        let mut intents = engine
            .outstanding_component_commit_intents(effect)
            .map_err(ToolDmaResumeError::Core)?;
        let tool_intent = take_component_intent(&mut intents, TOOL_DMA_COMPONENT_TOOL)?;
        let dma_intent = take_component_intent(&mut intents, TOOL_DMA_COMPONENT_DMA)?;
        if !intents.is_empty() {
            return Err(ToolDmaResumeError::UnexpectedCommitIntent);
        }

        let state = if parent.retained_claims == 0
            && matches!(
                parent.escape,
                EffectEscapeState::Retired | EffectEscapeState::Released
            ) {
            if tool_intent.is_some() || dma_intent.is_some() {
                return Err(ToolDmaResumeError::ImpossibleProjection);
            }
            ToolDmaResumeState::Terminal
        } else if tool_intent.is_some() || dma_intent.is_some() {
            ToolDmaResumeState::OutstandingCommits {
                tool: tool_intent.is_some(),
                dma: dma_intent.is_some(),
            }
        } else if matches!(tool.commit, cser_core::CommitState::Prepared)
            && matches!(dma.commit, cser_core::CommitState::Prepared)
        {
            ToolDmaResumeState::Prepared
        } else if parent.retained_claims > 0 {
            ToolDmaResumeState::Retained
        } else {
            return Err(ToolDmaResumeError::ImpossibleProjection);
        };

        Ok(ToolDmaResume {
            state,
            parent: Some(parent),
            tool: Some(tool),
            dma: Some(dma),
            tool_intent,
            dma_intent,
        })
    })
}

fn take_component_intent(
    intents: &mut alloc::vec::Vec<CommitIntent>,
    component: cser_core::ComponentId,
) -> Result<Option<CommitIntent>, ToolDmaResumeError> {
    let mut found = None;
    let mut index = 0;
    while index < intents.len() {
        if intents[index].component() == Some(component) {
            if found.is_some() {
                return Err(ToolDmaResumeError::UnexpectedCommitIntent);
            }
            found = Some(intents.swap_remove(index));
        } else {
            index += 1;
        }
    }
    Ok(found)
}

fn expect_none<E, B>(
    result: Result<cser_core::TransitionReceipt, TxError<E>>,
) -> Result<(), ToolDmaExperimentError<E, B>> {
    match result
        .map_err(ToolDmaExperimentError::Transition)?
        .into_output()
    {
        TransitionOutput::None => Ok(()),
        _ => Err(ToolDmaExperimentError::UnexpectedTransitionOutput),
    }
}

fn split_intents<E, B>(
    output: TransitionOutput,
) -> Result<(CommitIntent, CommitIntent), ToolDmaExperimentError<E, B>> {
    let TransitionOutput::CompositeCommitIntents(mut intents) = output else {
        return Err(ToolDmaExperimentError::UnexpectedTransitionOutput);
    };
    let tool_index = intents
        .iter()
        .position(|intent| intent.component() == Some(TOOL_DMA_COMPONENT_TOOL))
        .ok_or(ToolDmaExperimentError::MissingToolIntent)?;
    let tool = intents.swap_remove(tool_index);
    let dma_index = intents
        .iter()
        .position(|intent| intent.component() == Some(TOOL_DMA_COMPONENT_DMA))
        .ok_or(ToolDmaExperimentError::MissingDmaIntent)?;
    let dma = intents.swap_remove(dma_index);
    if !intents.is_empty() || tool.effect() != dma.effect() {
        return Err(ToolDmaExperimentError::UnexpectedTransitionOutput);
    }
    Ok((tool, dma))
}

#[cfg(ktest)]
mod tests {
    use core::convert::Infallible;

    use cser_core::{
        BootGeneration, DeviceGeneration, JournalGeneration, JournalRecord, PrincipalId,
        RegistryInstance, RootId,
    };
    use ostd::prelude::ktest;

    use super::*;

    struct TestDurability;

    impl TransitionDurability for TestDurability {
        type Error = Infallible;

        fn persist_transition(
            &mut self,
            record: &JournalRecord,
            resulting_freshness: Freshness,
        ) -> Result<(), Self::Error> {
            assert!(!record.bytes().is_empty());
            assert_ne!(resulting_freshness.boot().get(), 0);
            Ok(())
        }
    }

    struct NoopBarriers;

    impl ToolDmaBarrierHook for NoopBarriers {
        type Error = Infallible;

        fn reached(&mut self, _barrier: ToolDmaBarrier) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn freshness() -> Freshness {
        Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            1,
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        )
        .unwrap()
    }

    fn coordinates() -> ToolDmaCoordinates {
        let root = RootId::new(1).unwrap();
        let effect = EffectId::new(root, 1).unwrap();
        let actor = PrincipalIncarnation::new(PrincipalId::new(1).unwrap(), 1).unwrap();
        ToolDmaCoordinates::new(
            effect,
            actor,
            1,
            ChargeAccountId::new(1).unwrap(),
            ClaimId::new(1).unwrap(),
            ResourceId::new(1).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            ClaimId::new(2).unwrap(),
            ResourceId::new(2).unwrap(),
            ClaimId::new(3).unwrap(),
            ResourceId::new(3).unwrap(),
            ClaimId::new(4).unwrap(),
            ResourceId::new(4).unwrap(),
            DeviceScopeId::new(1).unwrap(),
            ResourceGeneration::new(1).unwrap(),
        )
        .unwrap()
    }

    #[ktest]
    fn crash_cutpoints_are_contiguous_and_ordered() {
        for (expected, barrier) in ToolDmaBarrier::ALL.iter().copied().enumerate() {
            assert_eq!(barrier.wire_id(), (expected + 1) as u16);
        }
    }

    #[ktest]
    fn resume_reconstructs_only_durable_component_intents() {
        let mut runtime = new_tool_dma_runtime(TestDurability, freshness());
        let coordinates = coordinates();
        let mut barriers = NoopBarriers;
        let armed = arm_tool_dma(
            &mut runtime,
            coordinates,
            [0x42; 16],
            b"tool-payload",
            Digest::new([0x55; 32]),
            &mut barriers,
        )
        .unwrap();
        drop(armed);

        let resumed = resume_tool_dma(&runtime, coordinates.effect()).unwrap();
        assert_eq!(
            resumed.state(),
            ToolDmaResumeState::OutstandingCommits {
                tool: true,
                dma: true,
            }
        );
        let (tool, dma) = resumed.into_outstanding_intents();
        assert_eq!(tool.unwrap().component(), Some(TOOL_DMA_COMPONENT_TOOL));
        assert_eq!(dma.unwrap().component(), Some(TOOL_DMA_COMPONENT_DMA));
    }

    #[ktest]
    fn resume_absent_has_no_reconstructed_authority() {
        let runtime = new_tool_dma_runtime(TestDurability, freshness());
        let effect = EffectId::new(RootId::new(9).unwrap(), 1).unwrap();
        let resumed = resume_tool_dma(&runtime, effect).unwrap();
        assert_eq!(resumed.state(), ToolDmaResumeState::Absent);
        assert_eq!(resumed.into_outstanding_intents(), (None, None));
    }
}
