// SPDX-License-Identifier: MPL-2.0

//! Tool-plus-DMA experiment orchestration primitives.
//!
//! This is intentionally not another persistent runtime.  Production already
//! has one `OstdCserRuntime` owner, one journal, and one ingress/fence path.
//! The experiment gives that owner a small component-local adapter: it records
//! the tool plan before POST, asks the endpoint for a durable observation, and
//! mints commands which affect *only* the tool component.  Existing DMA
//! adapters continue to own reset/IRQ/IOTLB quiescence and retire their own
//! component independently.

use cser_core::{
    ChargeAccountId, ChildDescriptorV1, Command, CommitIntent, CoreError, EffectId, Engine,
    PrincipalIncarnation, SettlementClaim, TOOL_DMA_COMPONENT_TOOL, TOOL_EVIDENCE_OUTCOME_ACK,
};

use super::core_tool_adapter::{
    DurableToolObservation, ToolChildDescriptorVerifier, ToolEndpoint, ToolEndpointObservation,
    ToolFactVerifier, ToolOperationPlan, ToolOutcomeVerifier,
};

/// The component-local tool half of one tool-plus-DMA composite effect.
///
/// The caller obtains `CommitIntent` and `SettlementClaim` only through the
/// shared durable runtime.  This type never constructs such authority and
/// never accepts a DMA component/claim coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolDmaRuntime {
    plan: ToolOperationPlan,
    verifier_epoch: u64,
}

impl ToolDmaRuntime {
    pub(crate) const fn new(plan: ToolOperationPlan, verifier_epoch: u64) -> Option<Self> {
        if verifier_epoch == 0 {
            None
        } else {
            Some(Self {
                plan,
                verifier_epoch,
            })
        }
    }

    pub(crate) const fn plan(self) -> ToolOperationPlan {
        self.plan
    }

    /// First dispatch.  The caller must only invoke this after the shared core
    /// has durably recorded `plan.operation_digest()` as the tool component's
    /// commit intent.
    pub(crate) fn submit<E: ToolEndpoint>(
        &self,
        endpoint: &mut E,
    ) -> Result<ToolEndpointObservation, E::Error> {
        endpoint.post(self.plan)
    }

    /// Recovery path for a possibly lost POST response.  It deliberately uses
    /// GET first; a transport may retry POST only with this immutable plan.
    pub(crate) fn recover<E: ToolEndpoint>(
        &self,
        endpoint: &mut E,
    ) -> Result<ToolEndpointObservation, E::Error> {
        endpoint.get(self.plan)
    }

    /// Verifies the endpoint's durable operation record and returns the sole
    /// command that can acknowledge the tool component's commit intent.
    pub(crate) fn acknowledge_commit(
        &self,
        engine: &Engine,
        intent: CommitIntent,
        observation: &DurableToolObservation,
    ) -> Result<Command, ToolCommitFailure> {
        if let Err(error) = self.require_tool_intent(&intent) {
            return Err(ToolCommitFailure { error, intent });
        }
        let verifier = match ToolFactVerifier::commit(self.plan, self.verifier_epoch) {
            Some(verifier) => verifier,
            None => {
                return Err(ToolCommitFailure {
                    error: CoreError::InvalidPayload,
                    intent,
                });
            }
        };
        let outcome = match engine.verify_commit_outcome(&intent, &verifier, observation) {
            Ok(outcome) => outcome,
            Err(error) => return Err(ToolCommitFailure { error, intent }),
        };
        intent
            .acknowledge(outcome)
            .map_err(|failure| ToolCommitFailure {
                error: failure.error().clone(),
                intent: failure.into_intent(),
            })
    }

    /// Evidence-bound source acknowledgement for the narrow CSER3 handoff.
    /// It consumes the parent component's linear commit intent and is the only
    /// ingress that can open the durable core handoff guard.
    pub(crate) fn acknowledge_handoff_parent_success(
        &self,
        engine: &Engine,
        intent: CommitIntent,
        observation: &DurableToolObservation,
    ) -> Result<(Command, ChildDescriptorV1), ToolCommitFailure> {
        if let Err(error) = self.require_handoff_intent(&intent) {
            return Err(ToolCommitFailure { error, intent });
        }
        let verifier = match ToolChildDescriptorVerifier::new(self.plan) {
            Some(verifier) => verifier,
            None => {
                return Err(ToolCommitFailure {
                    error: CoreError::InvalidPayload,
                    intent,
                });
            }
        };
        let descriptor = match verifier.decode(*observation) {
            Ok(descriptor) => descriptor,
            Err(_) => {
                return Err(ToolCommitFailure {
                    error: CoreError::VerificationFailed,
                    intent,
                });
            }
        };
        let verified = match engine.verify_child_descriptor(descriptor, &verifier, observation) {
            Ok(verified) => verified,
            Err(error) => return Err(ToolCommitFailure { error, intent }),
        };
        let outcome_verifier = match ToolFactVerifier::commit(self.plan, self.verifier_epoch) {
            Some(verifier) => verifier,
            None => {
                return Err(ToolCommitFailure {
                    error: CoreError::InvalidPayload,
                    intent,
                });
            }
        };
        let outcome = match engine.verify_commit_outcome(&intent, &outcome_verifier, observation) {
            Ok(outcome) => outcome,
            Err(error) => return Err(ToolCommitFailure { error, intent }),
        };
        let command = intent
            .acknowledge_handoff_parent_success(outcome, verified)
            .map_err(|failure| ToolCommitFailure {
                error: failure.error().clone(),
                intent: failure.into_intent(),
            })?;
        Ok((command, descriptor))
    }

    /// Atomically creates, enrolls, and prepares the single child through the
    /// core handoff guard. Re-verification on recovery prevents a stale local
    /// decoder cache from becoming authority.
    pub(crate) fn install_handoff_child(
        &self,
        engine: &Engine,
        observation: &DurableToolObservation,
        origin: PrincipalIncarnation,
        binding_generation: u64,
        charge_account: ChargeAccountId,
    ) -> Result<(Command, ChildDescriptorV1), CoreError> {
        let verifier =
            ToolChildDescriptorVerifier::new(self.plan).ok_or(CoreError::InvalidPayload)?;
        let descriptor = verifier
            .decode(*observation)
            .map_err(|_| CoreError::VerificationFailed)?;
        let verified = engine.verify_child_descriptor(descriptor, &verifier, observation)?;
        Ok((
            verified.install(origin, binding_generation, charge_account),
            descriptor,
        ))
    }

    /// Atomically releases the fully retired source and records the target's
    /// first commit intent. The operation is derived from the descriptor's
    /// complete evidence-bound identity rather than supplied by a caller.
    pub(crate) fn release_handoff_source_and_record_target_intent(
        &self,
        engine: &Engine,
        observation: &DurableToolObservation,
        actor: PrincipalIncarnation,
        binding_generation: u64,
    ) -> Result<Command, CoreError> {
        let verifier =
            ToolChildDescriptorVerifier::new(self.plan).ok_or(CoreError::InvalidPayload)?;
        let descriptor = verifier
            .decode(*observation)
            .map_err(|_| CoreError::VerificationFailed)?;
        let verified = engine.verify_child_descriptor(descriptor, &verifier, observation)?;
        let operation = handoff_operation_digest(descriptor, observation.terminal_record_digest());
        Ok(verified.release_source_and_record_target_intent(actor, binding_generation, operation))
    }

    /// Records that later settlement refers to the same durable endpoint
    /// record, rather than issuing a fresh external operation.
    pub(crate) fn record_reconciliation(
        &self,
        claim: SettlementClaim,
    ) -> Result<Command, ToolSettlementFailure> {
        if let Err(error) = self.require_tool_claim(&claim) {
            return Err(ToolSettlementFailure { error, claim });
        }
        claim
            .record_apply_intent(self.plan.reconciliation_digest())
            .map_err(|failure| ToolSettlementFailure {
                error: failure.error().clone(),
                claim: failure.into_claim(),
            })
    }

    /// Binds durable endpoint observation to the tool settlement's apply
    /// stage. This cannot release the DMA component.
    pub(crate) fn record_reconciled(
        &self,
        engine: &Engine,
        claim: SettlementClaim,
        observation: &DurableToolObservation,
    ) -> Result<Command, ToolSettlementFailure> {
        if let Err(error) = self.require_tool_claim(&claim) {
            return Err(ToolSettlementFailure { error, claim });
        }
        let verifier = match ToolFactVerifier::apply(self.plan, self.verifier_epoch) {
            Some(verifier) => verifier,
            None => {
                return Err(ToolSettlementFailure {
                    error: CoreError::InvalidPayload,
                    claim,
                });
            }
        };
        let applied = match engine.verify_apply_completion(&claim, &verifier, observation) {
            Ok(applied) => applied,
            Err(error) => return Err(ToolSettlementFailure { error, claim }),
        };
        claim
            .record_applied(applied)
            .map_err(|failure| ToolSettlementFailure {
                error: failure.error().clone(),
                claim: failure.into_claim(),
            })
    }

    /// Finalizes the tool's logical settlement from the same recoverable
    /// endpoint observation.  The endpoint is never called here.
    pub(crate) fn settle(
        &self,
        engine: &Engine,
        claim: SettlementClaim,
        observation: &DurableToolObservation,
    ) -> Result<Command, ToolSettlementFailure> {
        if let Err(error) = self.require_tool_claim(&claim) {
            return Err(ToolSettlementFailure { error, claim });
        }
        let verifier = match ToolFactVerifier::settlement(self.plan, self.verifier_epoch) {
            Some(verifier) => verifier,
            None => {
                return Err(ToolSettlementFailure {
                    error: CoreError::InvalidPayload,
                    claim,
                });
            }
        };
        let acknowledgement = match engine.verify_settlement_ack(&claim, &verifier, observation) {
            Ok(acknowledgement) => acknowledgement,
            Err(error) => return Err(ToolSettlementFailure { error, claim }),
        };
        claim
            .settle(acknowledgement)
            .map_err(|failure| ToolSettlementFailure {
                error: failure.error().clone(),
                claim: failure.into_claim(),
            })
    }

    /// Creates evidence only for the logical tool outcome claim.  The exact
    /// component and logical coordinate are checked again by the core verifier;
    /// passing DMA evidence or a DMA claim is structurally impossible here.
    pub(crate) fn retire_outcome(
        &self,
        engine: &Engine,
        observation: &DurableToolObservation,
    ) -> Result<Command, CoreError> {
        let verifier = ToolOutcomeVerifier::new(self.plan, self.verifier_epoch)
            .ok_or(CoreError::InvalidPayload)?;
        Ok(engine
            .verify_component_retirement_evidence(
                self.plan.effect(),
                TOOL_DMA_COMPONENT_TOOL,
                self.plan.claim(),
                TOOL_EVIDENCE_OUTCOME_ACK,
                &verifier,
                observation,
            )?
            .submit())
    }

    fn require_tool_intent(&self, intent: &CommitIntent) -> Result<(), CoreError> {
        if intent.effect() != self.plan.effect()
            || intent.component() != Some(TOOL_DMA_COMPONENT_TOOL)
        {
            return Err(CoreError::StaleCommitIntent);
        }
        Ok(())
    }

    fn require_handoff_intent(&self, intent: &CommitIntent) -> Result<(), CoreError> {
        if self.plan.component() != cser_core::TOOL_HANDOFF_SOURCE_COMPONENT
            || intent.effect() != self.plan.effect()
            || intent.component() != Some(self.plan.component())
        {
            return Err(CoreError::StaleCommitIntent);
        }
        Ok(())
    }

    fn require_tool_claim(&self, claim: &SettlementClaim) -> Result<(), CoreError> {
        if claim.effect() != self.plan.effect()
            || claim.component() != Some(TOOL_DMA_COMPONENT_TOOL)
        {
            return Err(CoreError::StaleSettlementClaim);
        }
        Ok(())
    }
}

fn handoff_operation_digest(
    descriptor: ChildDescriptorV1,
    terminal_record: cser_core::Digest,
) -> cser_core::Digest {
    use sha2::{Digest as _, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"nexus-cser-child-operation-v1");
    for field in [
        descriptor.route_digest.bytes(),
        descriptor.input_digest.bytes(),
        descriptor.catalog_digest.bytes(),
        terminal_record.bytes(),
    ] {
        hash.update((field.len() as u64).to_le_bytes());
        hash.update(field);
    }
    cser_core::Digest::new(hash.finalize().into())
}

/// A rejected tool commit acknowledgement which preserves the exact durable
/// component intent.  Endpoint parsing or verifier failure must never turn a
/// recoverable POST/GET observation failure into a lost write-ahead authority.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ToolCommitFailure {
    error: CoreError,
    intent: CommitIntent,
}

/// A rejected tool settlement transition which preserves the current linear
/// settlement claim.  A missing endpoint record or stale verifier cannot
/// silently discard the only durable reconciliation authority.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ToolSettlementFailure {
    error: CoreError,
    claim: SettlementClaim,
}

impl ToolSettlementFailure {
    pub(crate) const fn error(&self) -> &CoreError {
        &self.error
    }

    pub(crate) fn into_claim(self) -> SettlementClaim {
        self.claim
    }
}

impl ToolCommitFailure {
    pub(crate) const fn error(&self) -> &CoreError {
        &self.error
    }

    pub(crate) fn into_intent(self) -> CommitIntent {
        self.intent
    }
}

/// Exact component identity helper used by the production orchestration when
/// it selects the tool settlement after fencing/rebinding a root.
pub(crate) const fn tool_component(effect: EffectId) -> (EffectId, cser_core::ComponentId) {
    (effect, TOOL_DMA_COMPONENT_TOOL)
}

/// Kept here rather than in the UART transport: the currently active
/// successor is a core authority coordinate, not endpoint metadata.
pub(crate) const fn tool_settlement_actor(actor: PrincipalIncarnation) -> PrincipalIncarnation {
    actor
}
