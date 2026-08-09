// SPDX-License-Identifier: MPL-2.0

//! Adapter boundary for the queryable tool outcome used by the tool-plus-DMA
//! experiment.
//!
//! A UART reply is transport progress, never retirement evidence.  This module
//! accepts an observation only after the independently durable endpoint has
//! returned the operation key, payload digest, and result it recorded.  The
//! same plan is used for the first POST and every recovery GET/retry, so a
//! lost response cannot create a new external operation.

use cser_core::{
    ClaimId, ClaimScope, ComponentId, Digest, EffectFactChallenge, EffectFactKind, EffectId,
    EffectReceiptVerifier, EvidenceChallenge, ExternalOutcome, ReceiptVerifier, ResourceGeneration,
    ResourceId, TOOL_APPLY_RECEIPT_SCHEMA, TOOL_COMMIT_RECEIPT_SCHEMA, TOOL_DOMAIN,
    TOOL_EVIDENCE_OUTCOME_ACK, TOOL_OBLIGATION_INVOCATION, TOOL_RECEIPT_SCHEMA,
    TOOL_SETTLEMENT_RECEIPT_SCHEMA, TOOL_VERIFIER, VerificationError, VerifiedEffectObservation,
    VerifiedObservation, VerifierIdentity,
};
use sha2::{Digest as _, Sha256};

use super::core_tool_uart::{
    OperationKey, ToolRequest, ToolRunId, ToolTerminalOutcome, ToolTerminalRecord, ToolUart,
    ToolUartError, ToolV2Identity,
};

/// Must remain no larger than the bounded UART transport's payload limit.
const MAX_TOOL_PAYLOAD_BYTES: usize = 576;

/// Immutable pre-submit identity of one queryable tool operation.
///
/// `operation_digest` contains both the stable operation key and the payload
/// digest.  It must be recorded by the core before the adapter is allowed to
/// call POST.  A recovery path receives this value from the durable component
/// commit intent and may only issue GET or repeat POST with the same plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolOperationPlan {
    run_id: [u8; 16],
    catalog_digest: Digest,
    effect: EffectId,
    component: ComponentId,
    claim: ClaimId,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    operation_key: Digest,
    payload_digest: Digest,
    payload: [u8; MAX_TOOL_PAYLOAD_BYTES],
    payload_len: u16,
    operation_digest: Digest,
    transport_identity: Option<ToolV2Identity>,
}

impl ToolOperationPlan {
    pub(crate) fn new(
        run_id: [u8; 16],
        effect: EffectId,
        component: ComponentId,
        claim: ClaimId,
        resource: ResourceId,
        resource_generation: ResourceGeneration,
        catalog_digest: Digest,
        payload: &[u8],
    ) -> Result<Self, ToolPlanError> {
        if component != cser_core::TOOL_DMA_COMPONENT_TOOL || payload.is_empty() {
            return Err(ToolPlanError::InvalidCoordinate);
        }
        if payload.len() > MAX_TOOL_PAYLOAD_BYTES {
            return Err(ToolPlanError::PayloadTooLong);
        }
        let payload_digest = Digest::new(Sha256::digest(payload).into());
        let mut stored_payload = [0; MAX_TOOL_PAYLOAD_BYTES];
        stored_payload[..payload.len()].copy_from_slice(payload);
        let operation_key = hash_parts(
            b"nexus-cser-tool-key-v1",
            &[
                &effect.root().get().to_le_bytes(),
                &effect.sequence().to_le_bytes(),
                &component.get().to_le_bytes(),
                &claim.get().to_le_bytes(),
            ],
        );
        let operation_digest = hash_parts(
            b"nexus-cser-tool-operation-v1",
            &[
                &operation_key.bytes(),
                &payload_digest.bytes(),
                &run_id,
                &catalog_digest.bytes(),
                &resource.get().to_le_bytes(),
                &resource_generation.get().to_le_bytes(),
            ],
        );
        Ok(Self {
            run_id,
            catalog_digest,
            effect,
            component,
            claim,
            resource,
            resource_generation,
            operation_key,
            payload_digest,
            payload: stored_payload,
            payload_len: payload.len() as u16,
            operation_digest,
            transport_identity: None,
        })
    }

    pub(crate) fn bind_cser2(mut self, identity: ToolV2Identity) -> Self {
        // The durable commit operation is the recovery authority for an
        // idempotent external retry. Bind the complete transport identity
        // before that operation is recorded so a successor cannot adopt a
        // fresh host configuration and POST under a different endpoint key.
        let base = self.operation_digest.bytes();
        self.operation_digest = hash_parts(
            b"nexus-cser-tool-operation-v2",
            &[
                &base,
                identity.namespace(),
                &identity.authority().bytes(),
                &identity.effect().bytes(),
                &identity.catalog_digest(),
            ],
        );
        self.transport_identity = Some(identity);
        self
    }

    pub(crate) const fn effect(self) -> EffectId {
        self.effect
    }
    pub(crate) const fn run_id(self) -> [u8; 16] {
        self.run_id
    }
    pub(crate) const fn catalog_digest(self) -> Digest {
        self.catalog_digest
    }
    pub(crate) const fn component(self) -> ComponentId {
        self.component
    }
    pub(crate) const fn claim(self) -> ClaimId {
        self.claim
    }
    pub(crate) const fn resource(self) -> ResourceId {
        self.resource
    }
    pub(crate) const fn resource_generation(self) -> ResourceGeneration {
        self.resource_generation
    }
    pub(crate) const fn operation_key(self) -> Digest {
        self.operation_key
    }
    pub(crate) const fn payload_digest(self) -> Digest {
        self.payload_digest
    }
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload[..usize::from(self.payload_len)]
    }

    /// Canonical ASCII operation key for the UART/HTTP bridge.
    pub(crate) fn operation_key_hex(self) -> [u8; 64] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = [0; 64];
        for (index, byte) in self.operation_key.bytes().iter().copied().enumerate() {
            output[index * 2] = HEX[usize::from(byte >> 4)];
            output[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        output
    }
    pub(crate) const fn operation_digest(self) -> Digest {
        self.operation_digest
    }

    /// Stable settlement intent.  It deliberately names the already durable
    /// endpoint record rather than a second external action.
    pub(crate) fn reconciliation_digest(self) -> Digest {
        hash_parts(
            b"nexus-cser-tool-reconcile-v1",
            &[
                &self.operation_key.bytes(),
                &self.payload_digest.bytes(),
                &self.operation_digest.bytes(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolPlanError {
    InvalidCoordinate,
    PayloadTooLong,
}

/// Outcome recovered from the endpoint's own durable operation record.
///
/// This is constructible only from a checksum- and digest-verified terminal
/// record decoded by the UART codec. A bare POST reply and an arbitrary
/// non-zero digest cannot become CSER evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DurableToolObservation {
    plan: ToolOperationPlan,
    outcome: ExternalOutcome,
    endpoint_record_digest: Digest,
}

impl DurableToolObservation {
    pub(crate) fn from_terminal_record(
        plan: ToolOperationPlan,
        record: ToolTerminalRecord,
    ) -> Result<Self, ToolObservationError> {
        if record.run_id().bytes() != plan.run_id()
            || record.operation() != plan.operation_key_hex()
            || record.payload_digest() != plan.payload_digest().bytes()
        {
            return Err(ToolObservationError::PlanRecordMismatch);
        }
        let outcome = match record.outcome() {
            ToolTerminalOutcome::Success => ExternalOutcome::Success,
            ToolTerminalOutcome::Failure => ExternalOutcome::Failure,
        };
        let endpoint_record_digest = Digest::new(record.record_digest());
        Ok(Self {
            plan,
            outcome,
            endpoint_record_digest,
        })
    }

    pub(crate) const fn plan(self) -> ToolOperationPlan {
        self.plan
    }
    pub(crate) const fn outcome(self) -> ExternalOutcome {
        self.outcome
    }

    fn receipt_digest(self, label: &[u8]) -> Digest {
        hash_parts(
            label,
            &[
                &self.plan.operation_key().bytes(),
                &self.plan.payload_digest().bytes(),
                &self.plan.operation_digest().bytes(),
                &self.endpoint_record_digest.bytes(),
                &[match self.outcome {
                    ExternalOutcome::Success => 1,
                    ExternalOutcome::Failure => 2,
                }],
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolObservationError {
    PlanRecordMismatch,
}

/// Transport used by the runtime.  Implementations may POST on the initial
/// attempt, but recovery must use `get` first and may retry only this plan.
pub(crate) trait ToolEndpoint {
    type Error;

    fn post(&mut self, plan: ToolOperationPlan) -> Result<DurableToolObservation, Self::Error>;
    fn get(&mut self, plan: ToolOperationPlan) -> Result<DurableToolObservation, Self::Error>;
}

/// Concrete guest transport for the bounded endpoint. Both first dispatch and
/// reconciliation travel through the same strict record parser; recovery uses
/// GET and therefore cannot accidentally create a second operation.
pub(crate) struct UartToolEndpoint<'a> {
    uart: &'a mut ToolUart,
}

impl<'a> UartToolEndpoint<'a> {
    pub(crate) fn new(uart: &'a mut ToolUart) -> Self {
        Self { uart }
    }

    fn operation(plan: ToolOperationPlan) -> Result<OperationKey, ToolTransportError> {
        OperationKey::new(&plan.operation_key_hex()).map_err(ToolTransportError::Protocol)
    }

    fn observation(
        plan: ToolOperationPlan,
        reply: super::core_tool_uart::ToolResponse,
    ) -> Result<DurableToolObservation, ToolTransportError> {
        let record = reply
            .terminal_record()
            .ok_or(ToolTransportError::NoTerminalRecord {
                status: reply.status,
            })?;
        DurableToolObservation::from_terminal_record(plan, record)
            .map_err(ToolTransportError::Observation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolTransportError {
    Protocol(super::core_tool_uart::ToolProtocolError),
    Uart(ToolUartError),
    /// The bridge produced a checksum-valid response with no durable terminal
    /// record.  Recovery may retry the exact idempotent POST only for 404;
    /// timeouts, malformed frames and other HTTP statuses remain fail-closed.
    NoTerminalRecord {
        status: u16,
    },
    Observation(ToolObservationError),
}

impl ToolEndpoint for UartToolEndpoint<'_> {
    type Error = ToolTransportError;

    fn post(&mut self, plan: ToolOperationPlan) -> Result<DurableToolObservation, Self::Error> {
        let request = match plan.transport_identity {
            Some(identity) => ToolRequest::new_v2(
                identity,
                ToolRunId::new(plan.run_id()),
                Self::operation(plan)?,
                plan.payload(),
            ),
            None => ToolRequest::new(
                ToolRunId::new(plan.run_id()),
                Self::operation(plan)?,
                plan.payload(),
            ),
        }
        .map_err(ToolTransportError::Protocol)?;
        let reply = self
            .uart
            .transact(&request)
            .map_err(ToolTransportError::Uart)?;
        Self::observation(plan, reply)
    }

    fn get(&mut self, plan: ToolOperationPlan) -> Result<DurableToolObservation, Self::Error> {
        let request = match plan.transport_identity {
            Some(identity) => ToolRequest::get_v2(
                identity,
                ToolRunId::new(plan.run_id()),
                Self::operation(plan)?,
                plan.payload_digest().bytes(),
            ),
            None => ToolRequest::get(
                ToolRunId::new(plan.run_id()),
                Self::operation(plan)?,
                plan.payload_digest().bytes(),
            ),
        };
        let reply = self
            .uart
            .transact(&request)
            .map_err(ToolTransportError::Uart)?;
        Self::observation(plan, reply)
    }
}

/// One verifier whose schema differentiates commit, settlement, and
/// retirement facts while every fact still originates in the same endpoint
/// record.  It has no authority over DMA claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolOutcomeVerifier {
    plan: ToolOperationPlan,
    epoch: u64,
}

impl ToolOutcomeVerifier {
    pub(crate) const fn new(plan: ToolOperationPlan, epoch: u64) -> Option<Self> {
        if epoch == 0 {
            None
        } else {
            Some(Self { plan, epoch })
        }
    }

    fn identity_for(self, schema: cser_core::ReceiptSchemaId) -> VerifierIdentity {
        VerifierIdentity::new(TOOL_VERIFIER, self.epoch, schema)
            .expect("non-zero tool verifier epoch and static schema are valid")
    }

    fn exact_observation(self, observation: &DurableToolObservation) -> bool {
        observation.plan == self.plan
    }
}

impl EffectReceiptVerifier for ToolOutcomeVerifier {
    type Receipt = DurableToolObservation;

    fn identity(&self) -> VerifierIdentity {
        // EffectReceiptVerifier's identity is checked before `verify`; the
        // runtime selects a stage-specific wrapper below.
        self.identity_for(TOOL_COMMIT_RECEIPT_SCHEMA)
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        observation: &DurableToolObservation,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        if !self.exact_observation(observation)
            || challenge.effect() != self.plan.effect()
            || challenge.component() != Some(self.plan.component())
            || challenge.domain() != TOOL_DOMAIN
            || challenge.obligation() != TOOL_OBLIGATION_INVOCATION
            || challenge.expected_verifier() != TOOL_VERIFIER
        {
            return Err(VerificationError::Rejected);
        }
        match challenge.kind() {
            EffectFactKind::CommitOutcome
                if challenge.expected_receipt_schema() == TOOL_COMMIT_RECEIPT_SCHEMA
                    && challenge.operation() == self.plan.operation_digest() =>
            {
                Ok(VerifiedEffectObservation::commit(
                    challenge.current_observation(),
                    observation.outcome(),
                    observation.receipt_digest(b"nexus-cser-tool-commit-v1"),
                ))
            }
            // Settlement does not execute another tool call: it only binds the
            // durable endpoint observation to the core's settlement intent.
            EffectFactKind::ApplyCompleted
                if challenge.expected_receipt_schema() == TOOL_APPLY_RECEIPT_SCHEMA
                    && challenge.operation() == self.plan.reconciliation_digest() =>
            {
                Ok(VerifiedEffectObservation::fact(
                    challenge.current_observation(),
                    observation.receipt_digest(b"nexus-cser-tool-apply-v1"),
                ))
            }
            EffectFactKind::SettlementAcknowledged
                if challenge.expected_receipt_schema() == TOOL_SETTLEMENT_RECEIPT_SCHEMA
                    && challenge.operation() == self.plan.reconciliation_digest()
                    && challenge.predecessor()
                        == Some(observation.receipt_digest(b"nexus-cser-tool-apply-v1")) =>
            {
                Ok(VerifiedEffectObservation::fact(
                    challenge.current_observation(),
                    observation.receipt_digest(b"nexus-cser-tool-settle-v1"),
                ))
            }
            _ => Err(VerificationError::Rejected),
        }
    }
}

/// Stage-specific identity wrapper.  The portable verifier trait authenticates
/// the expected schema before dispatching to `ToolOutcomeVerifier`, so we use
/// one value for each fact stage rather than weakening that check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolFactVerifier {
    inner: ToolOutcomeVerifier,
    schema: cser_core::ReceiptSchemaId,
}

impl ToolFactVerifier {
    pub(crate) const fn commit(plan: ToolOperationPlan, epoch: u64) -> Option<Self> {
        match ToolOutcomeVerifier::new(plan, epoch) {
            Some(inner) => Some(Self {
                inner,
                schema: TOOL_COMMIT_RECEIPT_SCHEMA,
            }),
            None => None,
        }
    }
    pub(crate) const fn apply(plan: ToolOperationPlan, epoch: u64) -> Option<Self> {
        match ToolOutcomeVerifier::new(plan, epoch) {
            Some(inner) => Some(Self {
                inner,
                schema: TOOL_APPLY_RECEIPT_SCHEMA,
            }),
            None => None,
        }
    }
    pub(crate) const fn settlement(plan: ToolOperationPlan, epoch: u64) -> Option<Self> {
        match ToolOutcomeVerifier::new(plan, epoch) {
            Some(inner) => Some(Self {
                inner,
                schema: TOOL_SETTLEMENT_RECEIPT_SCHEMA,
            }),
            None => None,
        }
    }
}

impl EffectReceiptVerifier for ToolFactVerifier {
    type Receipt = DurableToolObservation;

    fn identity(&self) -> VerifierIdentity {
        self.inner.identity_for(self.schema)
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        EffectReceiptVerifier::verify(&self.inner, challenge, receipt)
    }
}

impl ReceiptVerifier for ToolOutcomeVerifier {
    type Receipt = DurableToolObservation;

    fn identity(&self) -> VerifierIdentity {
        self.identity_for(TOOL_RECEIPT_SCHEMA)
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        observation: &DurableToolObservation,
    ) -> Result<VerifiedObservation, VerificationError> {
        if !self.exact_observation(observation)
            || challenge.effect() != self.plan.effect()
            || challenge.component() != Some(self.plan.component())
            || challenge.claim() != self.plan.claim()
            || challenge.domain() != TOOL_DOMAIN
            || challenge.kind() != TOOL_EVIDENCE_OUTCOME_ACK
            || challenge.scope() != ClaimScope::Logical
            || challenge.resource() != self.plan.resource()
            || challenge.resource_generation() != self.plan.resource_generation()
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new(
            challenge.subject(),
            challenge.current_observation(),
            observation.receipt_digest(b"nexus-cser-tool-retirement-v1"),
        ))
    }
}

fn hash_parts(label: &[u8], parts: &[&[u8]]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(label);
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    Digest::new(hasher.finalize().into())
}

#[cfg(ktest)]
mod tests {
    use super::*;
    use crate::core_tool_uart::{
        OperationKey, ToolResponse, ToolRunId, ToolV2Identity, terminal_record_for_test,
    };
    use cser_core::{ClaimId, ComponentId, EffectId, ResourceGeneration, ResourceId, RootId};

    #[test]
    fn plan_binds_key_and_payload_before_submit() {
        let effect = EffectId::new(RootId::new(7).unwrap(), 9).unwrap();
        let plan = ToolOperationPlan::new(
            [0x12; 16],
            effect,
            cser_core::TOOL_DMA_COMPONENT_TOOL,
            ClaimId::new(11).unwrap(),
            ResourceId::new(12).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            Digest::new([0x77; 32]),
            b"first payload",
        )
        .unwrap();
        let changed_payload = ToolOperationPlan::new(
            [0x12; 16],
            effect,
            ComponentId::new(3).unwrap(),
            ClaimId::new(11).unwrap(),
            ResourceId::new(12).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            Digest::new([0x77; 32]),
            b"second payload",
        )
        .unwrap();
        assert_ne!(plan.operation_key(), Digest::ZERO);
        assert_ne!(plan.operation_digest(), changed_payload.operation_digest());
        assert_eq!(plan.operation_key(), changed_payload.operation_key());
    }

    #[test]
    fn cser2_plan_digest_binds_complete_recovery_identity() {
        let effect = EffectId::new(RootId::new(7).unwrap(), 9).unwrap();
        let base = ToolOperationPlan::new(
            [0x12; 16],
            effect,
            cser_core::TOOL_DMA_COMPONENT_TOOL,
            ClaimId::new(11).unwrap(),
            ResourceId::new(12).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            Digest::new([0x77; 32]),
            b"payload",
        )
        .unwrap();
        let first = base.bind_cser2(
            ToolV2Identity::new(
                b"tool",
                ToolRunId::new([0xa1; 16]),
                ToolRunId::new([0xb1; 16]),
                [0x77; 32],
            )
            .unwrap(),
        );
        let changed_authority = base.bind_cser2(
            ToolV2Identity::new(
                b"tool",
                ToolRunId::new([0xa2; 16]),
                ToolRunId::new([0xb1; 16]),
                [0x77; 32],
            )
            .unwrap(),
        );
        assert_ne!(base.operation_digest(), first.operation_digest());
        assert_ne!(
            first.operation_digest(),
            changed_authority.operation_digest()
        );
    }

    #[test]
    fn observation_requires_the_exact_decoded_terminal_record() {
        let effect = EffectId::new(RootId::new(7).unwrap(), 9).unwrap();
        let plan = ToolOperationPlan::new(
            [0x33; 16],
            effect,
            cser_core::TOOL_DMA_COMPONENT_TOOL,
            ClaimId::new(11).unwrap(),
            ResourceId::new(12).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            Digest::new([0x77; 32]),
            b"payload",
        )
        .unwrap();
        let matching = terminal_record_for_test(
            ToolRunId::new([0x33; 16]),
            OperationKey::new(&plan.operation_key_hex()).unwrap(),
            b"payload",
        );
        assert!(DurableToolObservation::from_terminal_record(plan, matching).is_ok());
        let wrong_payload = terminal_record_for_test(
            ToolRunId::new([0x33; 16]),
            OperationKey::new(&plan.operation_key_hex()).unwrap(),
            b"changed",
        );
        assert_eq!(
            DurableToolObservation::from_terminal_record(plan, wrong_payload),
            Err(ToolObservationError::PlanRecordMismatch),
        );
    }

    #[test]
    fn only_a_checksum_valid_404_is_classified_as_an_absent_endpoint_record() {
        let effect = EffectId::new(RootId::new(7).unwrap(), 9).unwrap();
        let plan = ToolOperationPlan::new(
            [0x33; 16],
            effect,
            cser_core::TOOL_DMA_COMPONENT_TOOL,
            ClaimId::new(11).unwrap(),
            ResourceId::new(12).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            Digest::new([0x77; 32]),
            b"payload",
        )
        .unwrap();
        assert_eq!(
            UartToolEndpoint::observation(plan, ToolResponse::missing_terminal_for_test(404)),
            Err(ToolTransportError::NoTerminalRecord { status: 404 }),
        );
        assert_eq!(
            UartToolEndpoint::observation(plan, ToolResponse::missing_terminal_for_test(500)),
            Err(ToolTransportError::NoTerminalRecord { status: 500 }),
        );
    }
}
