// SPDX-License-Identifier: MPL-2.0

//! Narrow, logical-only CSER3 single-hop handoff primitives.
//!
//! This is deliberately separate from the Tool+DMA experiment: it creates a
//! one-component logical source (catalog component 6), consumes the source
//! provider's CSER3 descriptor, and creates the one-component logical child
//! (catalog component 5).  No device coordinate is allocated, observed, or
//! retired in this lane.

use cser_core::{
    ChargeAccountId, ClaimId, ClaimScope, CommandRequest, CommitIntent, CoreError, Digest,
    EffectId, Engine, PrincipalIncarnation, ResourceGeneration, ResourceId,
    TOOL_CLAIM_OUTCOME_SLOT, TOOL_HANDOFF_SOURCE_COMPONENT, TOOL_HANDOFF_SOURCE_COMPOSITE,
    TransitionDurability, TransitionOutput,
};

use super::{
    core_runtime::OstdCserRuntime,
    core_tool_adapter::{DurableToolObservation, ToolOperationPlan},
    core_tool_dma_runtime::ToolDmaRuntime,
};

/// Stable COM3 cutpoint numbers for the handoff lane.  They are intentionally
/// unrelated to the Tool+DMA seven-cut matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandoffBarrier {
    DescriptorDiscovered = 21,
    ParentAcknowledged = 22,
    ChildInstalled = 23,
    HandoffCommittedBeforeChildPost = 24,
    TerminalReceipt = 25,
}

impl HandoffBarrier {
    pub(crate) const fn wire_id(self) -> u8 {
        self as u8
    }
}

/// The complete durable input coordinate for a source arm.  The source plan
/// itself is the exact operation identity; no host-supplied child identity is
/// accepted here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HandoffSourceCoordinates {
    pub(crate) effect: EffectId,
    pub(crate) actor: PrincipalIncarnation,
    pub(crate) binding_generation: u64,
    pub(crate) charge_account: ChargeAccountId,
    pub(crate) claim: ClaimId,
    pub(crate) resource: ResourceId,
    pub(crate) resource_generation: ResourceGeneration,
}

/// Creates and write-ahead-arms the fixed logical source.  The caller must
/// POST only after this returns its linear intent.
pub(crate) fn arm_handoff_source<P: TransitionDurability>(
    runtime: &mut OstdCserRuntime<P>,
    coordinates: HandoffSourceCoordinates,
    source: ToolOperationPlan,
) -> Result<CommitIntent, CoreError> {
    if !source.is_cser3_source()
        || source.effect() != coordinates.effect
        || source.component() != TOOL_HANDOFF_SOURCE_COMPONENT
        || source.claim() != coordinates.claim
        || source.resource() != coordinates.resource
        || source.resource_generation() != coordinates.resource_generation
    {
        return Err(CoreError::InvalidPayload);
    }
    expect_none(must_transact(
        runtime,
        CommandRequest::CreateCompositeEffect {
            effect: coordinates.effect,
            origin: coordinates.actor,
            binding_generation: coordinates.binding_generation,
            kind: TOOL_HANDOFF_SOURCE_COMPOSITE,
            charge_account: coordinates.charge_account,
        },
    ))?;
    expect_none(must_transact(
        runtime,
        CommandRequest::AddComponentClaim {
            effect: coordinates.effect,
            component: TOOL_HANDOFF_SOURCE_COMPONENT,
            actor: coordinates.actor,
            binding_generation: coordinates.binding_generation,
            claim: coordinates.claim,
            kind: TOOL_CLAIM_OUTCOME_SLOT,
            scope: ClaimScope::Logical,
            resource: coordinates.resource,
            resource_generation: coordinates.resource_generation,
            units: 1,
        },
    ))?;
    expect_none(must_transact(
        runtime,
        CommandRequest::PrepareCompositeEffect {
            effect: coordinates.effect,
            actor: coordinates.actor,
            binding_generation: coordinates.binding_generation,
        },
    ))?;
    match must_transact(
        runtime,
        CommandRequest::RecordComponentCommitIntent {
            effect: coordinates.effect,
            component: TOOL_HANDOFF_SOURCE_COMPONENT,
            actor: coordinates.actor,
            binding_generation: coordinates.binding_generation,
            operation: source.operation_digest(),
        },
    )
    .into_output()
    {
        TransitionOutput::CommitIntent(intent) => Ok(intent),
        _ => Err(CoreError::InvariantViolation),
    }
}

/// Acknowledges the successful source observation and returns its canonical
/// descriptor.  Descriptor verification and the acknowledgement are one core
/// command, so formatting a UART reply cannot create a handoff state.
pub(crate) fn acknowledge_source<P: TransitionDurability>(
    runtime: &mut OstdCserRuntime<P>,
    source: ToolDmaRuntime,
    intent: CommitIntent,
    observation: &DurableToolObservation,
) -> Result<cser_core::ChildDescriptorV1, CoreError> {
    let (command, descriptor) = runtime
        .observe(|engine| source.acknowledge_handoff_parent_success(engine, intent, observation))
        .map_err(|failure| failure.error().clone())?;
    expect_none(must_transact(runtime, command))?;
    Ok(descriptor)
}

/// Settles and retires the exact logical component using the same durable
/// record.  This must happen before the handoff guard permits source release.
pub(crate) fn settle_and_retire<P: TransitionDurability>(
    runtime: &mut OstdCserRuntime<P>,
    effect: EffectId,
    component: cser_core::ComponentId,
    claimant: PrincipalIncarnation,
    tool: ToolDmaRuntime,
    observation: &DurableToolObservation,
) -> Result<(), CoreError> {
    let claim = match must_transact(
        runtime,
        CommandRequest::ClaimComponentSettlement {
            effect,
            component,
            claimant,
        },
    )
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        _ => return Err(CoreError::InvariantViolation),
    };
    let claim = match tool.record_reconciliation(claim) {
        Ok(command) => match must_transact(runtime, command).into_output() {
            TransitionOutput::SettlementClaim(claim) => claim,
            _ => return Err(CoreError::InvariantViolation),
        },
        Err(failure) if failure.error() == &CoreError::WrongSettlementStage => failure.into_claim(),
        Err(failure) => return Err(failure.error().clone()),
    };
    let command = runtime
        .observe(|engine| tool.record_reconciled(engine, claim, observation))
        .map_err(|failure| failure.error().clone())?;
    let claim = match must_transact(runtime, command).into_output() {
        TransitionOutput::SettlementClaim(claim) => claim,
        _ => return Err(CoreError::InvariantViolation),
    };
    let command = runtime
        .observe(|engine| tool.settle(engine, claim, observation))
        .map_err(|failure| failure.error().clone())?;
    expect_none(must_transact(runtime, command))?;
    let command = runtime.observe(|engine| tool.retire_outcome(engine, observation))?;
    expect_none(must_transact(runtime, command))?;
    Ok(())
}

/// Installs the verified child as its own durable transition.  The caller
/// deliberately retains both source and child custody until the source has
/// been settled and retired; this overlap avoids a custody gap.
pub(crate) fn install_child<P: TransitionDurability>(
    runtime: &mut OstdCserRuntime<P>,
    source: ToolDmaRuntime,
    observation: &DurableToolObservation,
    actor: PrincipalIncarnation,
    binding_generation: u64,
    charge_account: ChargeAccountId,
) -> Result<cser_core::ChildDescriptorV1, CoreError> {
    let (command, descriptor) = runtime.observe(|engine| {
        source.install_handoff_child(
            engine,
            observation,
            actor,
            binding_generation,
            charge_account,
        )
    })?;
    expect_none(must_transact(runtime, command))?;
    Ok(descriptor)
}

/// The authority pivot occurs only after source retirement: atomically
/// releases the source and records the child intent. The returned linear
/// intent is the only authority to issue the child POST.
pub(crate) fn release_source_and_record_child_intent<P: TransitionDurability>(
    runtime: &mut OstdCserRuntime<P>,
    source: ToolDmaRuntime,
    observation: &DurableToolObservation,
    child: ToolOperationPlan,
    actor: PrincipalIncarnation,
    binding_generation: u64,
) -> Result<CommitIntent, CoreError> {
    if !child.is_cser3_child() {
        return Err(CoreError::InvalidPayload);
    }
    let descriptor = runtime.observe(|engine| {
        let verifier = super::core_tool_adapter::ToolChildDescriptorVerifier::new(source.plan())
            .ok_or(CoreError::InvalidPayload)?;
        let descriptor = verifier
            .decode(*observation)
            .map_err(|_| CoreError::VerificationFailed)?;
        engine.verify_child_descriptor(descriptor, &verifier, observation)?;
        Ok::<_, CoreError>(descriptor)
    })?;
    let command = runtime.observe(|engine| {
        source.release_handoff_source_and_record_target_intent(
            engine,
            observation,
            child,
            actor,
            binding_generation,
        )
    })?;
    match must_transact(runtime, command).into_output() {
        TransitionOutput::CommitIntent(intent)
            if intent.effect()
                == descriptor
                    .child_effect()
                    .map_err(|_| CoreError::InvalidPayload)? =>
        {
            Ok(intent)
        }
        _ => Err(CoreError::InvariantViolation),
    }
}

fn expect_none(receipt: cser_core::TransitionReceipt) -> Result<(), CoreError> {
    if matches!(receipt.into_output(), TransitionOutput::None) {
        Ok(())
    } else {
        Err(CoreError::InvariantViolation)
    }
}

fn must_transact<P: TransitionDurability, C: Into<cser_core::Command>>(
    runtime: &OstdCserRuntime<P>,
    command: C,
) -> cser_core::TransitionReceipt {
    runtime
        .transact(command)
        .unwrap_or_else(|_| panic!("CSER_HANDOFF_FAIL stage=durable-transition"))
}

/// A bounded digest helper used by terminal receipts without exposing any
/// unbound host state as experiment authority.
pub(crate) fn descriptor_digest(descriptor: cser_core::ChildDescriptorV1) -> Digest {
    use sha2::{Digest as _, Sha256};
    Digest::new(Sha256::digest(descriptor.encode_wire()).into())
}
