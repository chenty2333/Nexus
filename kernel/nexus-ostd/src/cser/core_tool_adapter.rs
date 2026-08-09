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
    ChargeAccountId, ClaimId, ClaimScope, CommandRequest, ComponentId, Digest, EffectFactChallenge,
    EffectFactKind, EffectId, EffectReceiptVerifier, EvidenceChallenge, ExternalOutcome,
    HandoffChildResolutionVerifier, HandoffResolutionChallenge, HandoffResolutionVerifier,
    PrincipalIncarnation, ReceiptVerifier, ResourceGeneration, ResourceId, RootId,
    TOOL_APPLY_RECEIPT_SCHEMA, TOOL_CLAIM_OUTCOME_SLOT, TOOL_COMMIT_RECEIPT_SCHEMA, TOOL_DOMAIN,
    TOOL_EVIDENCE_OUTCOME_ACK, TOOL_OBLIGATION_INVOCATION, TOOL_RECEIPT_SCHEMA,
    TOOL_SETTLEMENT_RECEIPT_SCHEMA, TOOL_VERIFIER, VerificationError, VerifiedEffectObservation,
    VerifiedObservation, VerifierIdentity,
};
use sha2::{Digest as _, Sha256};

use super::core_tool_uart::{
    OperationKey, ToolRequest, ToolResponse, ToolResponseState, ToolRunId, ToolTerminalOutcome,
    ToolTerminalOutput, ToolTerminalOutputKind, ToolTerminalRecord, ToolUart, ToolUartError,
    ToolV2Identity,
};

/// Must remain no larger than the bounded UART transport's payload limit.
const MAX_TOOL_PAYLOAD_BYTES: usize = 576;

/// SHA-256("nexus-cser-tool-provider-child-route-v1"). This fixed provider
/// route is part of the descriptor receipt; callers cannot choose it.
const PROVIDER_CHILD_ROUTE: Digest = Digest::new([
    0x28, 0x73, 0x2d, 0x53, 0x5f, 0x4e, 0x48, 0xd4, 0x10, 0xef, 0x5b, 0x74, 0x93, 0x24, 0x56, 0x41,
    0xb3, 0x2d, 0xe7, 0xa5, 0xfa, 0x0d, 0xfa, 0x7b, 0x5d, 0xfc, 0xf0, 0x44, 0xfd, 0x00, 0x16, 0x0c,
]);

const fn provider_child_route() -> Digest {
    PROVIDER_CHILD_ROUTE
}

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
    cser3_bound: bool,
    cser3_output: bool,
    child_route: Option<Digest>,
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
        if component != cser_core::TOOL_DMA_COMPONENT_TOOL {
            return Err(ToolPlanError::InvalidCoordinate);
        }
        Self::new_restricted(
            run_id,
            effect,
            component,
            claim,
            resource,
            resource_generation,
            catalog_digest,
            payload,
        )
    }

    /// Source-side CSER3 plan for the catalog-defined handoff provider.
    pub(crate) fn handoff_source(
        run_id: [u8; 16],
        effect: EffectId,
        claim: ClaimId,
        resource: ResourceId,
        resource_generation: ResourceGeneration,
        catalog_digest: Digest,
        payload: &[u8],
    ) -> Result<Self, ToolPlanError> {
        Self::new_restricted(
            run_id,
            effect,
            cser_core::TOOL_HANDOFF_SOURCE_COMPONENT,
            claim,
            resource,
            resource_generation,
            catalog_digest,
            payload,
        )
    }

    /// Child-side plan constructor. It never enables CSER3 descriptor ingress:
    /// that authority belongs exclusively to the source provider above.
    pub(crate) fn handoff_child(
        run_id: [u8; 16],
        effect: EffectId,
        claim: ClaimId,
        resource: ResourceId,
        resource_generation: ResourceGeneration,
        catalog_digest: Digest,
        payload: &[u8],
    ) -> Result<Self, ToolPlanError> {
        Self::new_restricted(
            run_id,
            effect,
            cser_core::TOOL_HANDOFF_COMPONENT,
            claim,
            resource,
            resource_generation,
            catalog_digest,
            payload,
        )
    }

    fn new_restricted(
        run_id: [u8; 16],
        effect: EffectId,
        component: ComponentId,
        claim: ClaimId,
        resource: ResourceId,
        resource_generation: ResourceGeneration,
        catalog_digest: Digest,
        payload: &[u8],
    ) -> Result<Self, ToolPlanError> {
        if payload.is_empty() {
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
            cser3_bound: false,
            cser3_output: false,
            child_route: None,
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

    /// Select the output-bearing CSER3 wire contract for a discovered child.
    /// Existing tool/DMA profiles retain CSER2 and therefore cannot acquire a
    /// descriptor accidentally.
    pub(crate) fn bind_cser3(mut self, identity: ToolV2Identity) -> Self {
        if self.component != cser_core::TOOL_HANDOFF_SOURCE_COMPONENT {
            return self;
        }
        self.transport_identity = Some(identity);
        self.cser3_bound = true;
        self.cser3_output = true;
        self.child_route = Some(provider_child_route());
        self.operation_digest = hash_parts(
            b"nexus-cser-tool-operation-v3",
            &[
                &self.operation_digest.bytes(),
                &identity.request_binding_digest(
                    ToolRunId::new(self.run_id),
                    &self.operation_key_hex(),
                    self.payload_digest.bytes(),
                ),
            ],
        );
        self
    }

    /// Binds the child to the same CSER3 request grammar, but explicitly
    /// prohibits a second descriptor output.  The child terminal record is an
    /// ordinary, output-free durable outcome.
    pub(crate) fn bind_cser3_child(mut self, identity: ToolV2Identity) -> Self {
        if self.component != cser_core::TOOL_HANDOFF_COMPONENT {
            return self;
        }
        let base = self.operation_digest.bytes();
        self.operation_digest = hash_parts(
            b"nexus-cser-tool-child-operation-v3",
            &[
                &base,
                &identity.request_binding_digest(
                    ToolRunId::new(self.run_id),
                    &self.operation_key_hex(),
                    self.payload_digest.bytes(),
                ),
            ],
        );
        self.transport_identity = Some(identity);
        self.cser3_bound = true;
        self.cser3_output = false;
        self
    }

    /// Creates the only child operation accepted by the single-hop runtime.
    /// Every field comes from the verified descriptor and source transport
    /// identity; callers cannot select a child run, endpoint effect, or
    /// payload.
    pub(crate) fn handoff_child_for_descriptor(
        source: ToolOperationPlan,
        descriptor: cser_core::ChildDescriptorV1,
    ) -> Result<Self, ToolPlanError> {
        if !source.is_cser3_source()
            || descriptor.parent != source.effect
            || descriptor.parent_component != source.component
            || descriptor.catalog_digest != source.catalog_digest
            || descriptor.input_digest != source.payload_digest
        {
            return Err(ToolPlanError::InvalidCoordinate);
        }
        let effect = descriptor
            .child_effect()
            .map_err(|_| ToolPlanError::InvalidCoordinate)?;
        let identity = source
            .transport_identity
            .ok_or(ToolPlanError::InvalidCoordinate)?;
        Self::handoff_child(
            source.run_id(),
            effect,
            descriptor.claim,
            descriptor.resource,
            descriptor.resource_generation,
            descriptor.catalog_digest,
            &handoff_child_payload(descriptor).bytes(),
        )
        .map(|plan| plan.bind_cser3_child(handoff_child_transport_identity(source, identity)))
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
    pub(crate) const fn child_route(self) -> Option<Digest> {
        self.child_route
    }
    /// Exact checksum-bound transport identity selected before durable intent.
    /// This is read-only recovery metadata, never endpoint authority.
    pub(crate) const fn transport_identity(self) -> Option<ToolV2Identity> {
        self.transport_identity
    }
    pub(crate) const fn is_cser3_source(self) -> bool {
        self.cser3_bound && self.cser3_output
    }
    pub(crate) fn is_cser3_child(self) -> bool {
        self.cser3_bound
            && !self.cser3_output
            && self.component == cser_core::TOOL_HANDOFF_COMPONENT
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

/// Derives the child endpoint effect from the complete parent transport
/// identity. Kept crate-visible for the QEMU runtime and host golden vectors.
pub(crate) fn handoff_child_transport_effect(
    parent: ToolV2Identity,
    source_run_id: [u8; 16],
) -> ToolRunId {
    let digest = hash_parts(
        b"nexus-cser-handoff-child-transport-effect-v1",
        &[
            parent.namespace(),
            &parent.authority().bytes(),
            &parent.effect().bytes(),
            &source_run_id,
            &parent.catalog_digest(),
        ],
    );
    let mut effect = [0; 16];
    effect.copy_from_slice(&digest.bytes()[..16]);
    ToolRunId::new(effect)
}

/// The child request payload is a digest of the complete canonical descriptor,
/// not a caller-supplied workflow argument.
pub(crate) fn handoff_child_payload(descriptor: cser_core::ChildDescriptorV1) -> Digest {
    hash_parts(
        b"nexus-cser-tool-handoff-child-payload-v1",
        &[&descriptor.encode_wire()],
    )
}

fn handoff_child_transport_identity(
    source: ToolOperationPlan,
    parent: ToolV2Identity,
) -> ToolV2Identity {
    ToolV2Identity::new(
        parent.namespace(),
        parent.authority(),
        handoff_child_transport_effect(parent, source.run_id()),
        parent.catalog_digest(),
    )
    .expect("parent identity is already canonical")
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
    terminal_output: ToolTerminalOutput,
}

impl DurableToolObservation {
    pub(crate) fn from_terminal_record(
        plan: ToolOperationPlan,
        record: ToolTerminalRecord,
    ) -> Result<Self, ToolObservationError> {
        if record.run_id().bytes() != plan.run_id()
            || record.operation() != plan.operation_key_hex()
            || record.payload_digest() != plan.payload_digest().bytes()
            || (plan.is_cser3_source()
                && record.output().kind() != ToolTerminalOutputKind::ChildDescriptorV1)
            || (plan.is_cser3_child() && record.output().kind() != ToolTerminalOutputKind::None)
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
            terminal_output: record.output(),
        })
    }

    pub(crate) const fn plan(self) -> ToolOperationPlan {
        self.plan
    }
    pub(crate) const fn outcome(self) -> ExternalOutcome {
        self.outcome
    }
    pub(crate) const fn terminal_output(self) -> ToolTerminalOutput {
        self.terminal_output
    }
    pub(crate) const fn terminal_record_digest(self) -> Digest {
        self.endpoint_record_digest
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

/// The complete endpoint observation vocabulary exposed to the guest
/// orchestrator.  `Accepted` and `Pending` deliberately remain nonterminal:
/// neither permits a second POST nor an effect/claim transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolEndpointObservation {
    Terminal(DurableToolObservation),
    Nonterminal(ToolNonterminalState),
    Absent,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolNonterminalState {
    Accepted,
    Pending,
}

/// Transport used by the runtime.  Implementations may POST on the initial
/// attempt, but recovery must use `get` first and may retry only this plan.
pub(crate) trait ToolEndpoint {
    type Error;

    fn post(&mut self, plan: ToolOperationPlan) -> Result<ToolEndpointObservation, Self::Error>;
    fn get(&mut self, plan: ToolOperationPlan) -> Result<ToolEndpointObservation, Self::Error>;
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
        reply: ToolResponse,
    ) -> Result<ToolEndpointObservation, ToolTransportError> {
        match reply.state() {
            ToolResponseState::Terminal => {
                let record =
                    reply
                        .terminal_record()
                        .ok_or(ToolTransportError::NoTerminalRecord {
                            status: reply.status,
                        })?;
                DurableToolObservation::from_terminal_record(plan, record)
                    .map(ToolEndpointObservation::Terminal)
                    .map_err(ToolTransportError::Observation)
            }
            ToolResponseState::Accepted => Ok(ToolEndpointObservation::Nonterminal(
                ToolNonterminalState::Accepted,
            )),
            ToolResponseState::Pending => Ok(ToolEndpointObservation::Nonterminal(
                ToolNonterminalState::Pending,
            )),
            ToolResponseState::Absent => Ok(ToolEndpointObservation::Absent),
            ToolResponseState::Expired => Ok(ToolEndpointObservation::Expired),
            ToolResponseState::LegacyNonterminal => Err(ToolTransportError::NoTerminalRecord {
                status: reply.status,
            }),
        }
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

    fn post(&mut self, plan: ToolOperationPlan) -> Result<ToolEndpointObservation, Self::Error> {
        let request = match plan.transport_identity {
            Some(identity) if plan.cser3_bound => ToolRequest::new_v3(
                identity,
                ToolRunId::new(plan.run_id()),
                Self::operation(plan)?,
                plan.payload(),
            ),
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

    fn get(&mut self, plan: ToolOperationPlan) -> Result<ToolEndpointObservation, Self::Error> {
        let request = match plan.transport_identity {
            Some(identity) if plan.cser3_bound => ToolRequest::get_v3(
                identity,
                ToolRunId::new(plan.run_id()),
                Self::operation(plan)?,
                plan.payload_digest().bytes(),
            ),
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

/// Verifies a canonical core descriptor carried by one successful, durable
/// CSER3 terminal record. The descriptor is data; the resulting core token is
/// the only authority accepted by guarded handoff commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolChildDescriptorVerifier {
    plan: ToolOperationPlan,
}

impl ToolChildDescriptorVerifier {
    pub(crate) const fn new(plan: ToolOperationPlan) -> Option<Self> {
        if plan.cser3_output && plan.child_route.is_some() {
            Some(Self { plan })
        } else {
            None
        }
    }

    pub(crate) fn decode(
        &self,
        observation: DurableToolObservation,
    ) -> Result<cser_core::ChildDescriptorV1, ToolObservationError> {
        if observation.plan != self.plan || observation.outcome != ExternalOutcome::Success {
            return Err(ToolObservationError::PlanRecordMismatch);
        }
        decode_core_child_descriptor(observation.terminal_output)
    }
}

impl cser_core::ChildDescriptorVerifier for ToolChildDescriptorVerifier {
    type Receipt = DurableToolObservation;

    fn verify_child_descriptor(
        &self,
        descriptor: cser_core::ChildDescriptorV1,
        observation: &DurableToolObservation,
    ) -> Result<Digest, VerificationError> {
        if observation.plan != self.plan
            || observation.outcome != ExternalOutcome::Success
            || self
                .decode(*observation)
                .map_err(|_| VerificationError::Rejected)?
                != descriptor
            || descriptor.parent != self.plan.effect()
            || descriptor.parent_component != self.plan.component()
            || descriptor.catalog_digest != self.plan.catalog_digest()
            || descriptor.route_digest
                != self.plan.child_route().ok_or(VerificationError::Rejected)?
            || descriptor.input_digest != self.plan.payload_digest()
            || descriptor.schema != 1
            || descriptor.sequence != 1
        {
            return Err(VerificationError::Rejected);
        }
        Ok(hash_parts(
            b"nexus-cser-tool-child-descriptor-v1",
            &[
                &observation.endpoint_record_digest.bytes(),
                &descriptor.catalog_digest.bytes(),
                &descriptor.route_digest.bytes(),
                &descriptor.input_digest.bytes(),
            ],
        ))
    }
}

/// Dedicated verifier for refining a fenced parent from indeterminate to the
/// same durable terminal success observed by the source endpoint.  It cannot
/// mint or recover a commit nonce and is accepted only by the core's narrow
/// handoff-resolution transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolHandoffResolutionVerifier {
    inner: ToolOutcomeVerifier,
    /// Present only for target recovery. It pins the child verifier to the
    /// descriptor that derived its immutable operation plan.
    child_descriptor: Option<cser_core::ChildDescriptorV1>,
}

impl ToolHandoffResolutionVerifier {
    pub(crate) const fn new(plan: ToolOperationPlan, epoch: u64) -> Option<Self> {
        if !plan.cser3_output || plan.child_route.is_none() {
            return None;
        }
        match ToolOutcomeVerifier::new(plan, epoch) {
            Some(inner) => Some(Self {
                inner,
                child_descriptor: None,
            }),
            None => None,
        }
    }

    /// Builds the child-side verifier only for the exact descriptor-derived
    /// plan. This is deliberately distinct from [`Self::new`], which remains
    /// source-only and requires descriptor output authority.
    pub(crate) fn new_child(
        child: ToolOperationPlan,
        source: ToolOperationPlan,
        descriptor: cser_core::ChildDescriptorV1,
        epoch: u64,
    ) -> Option<Self> {
        if !child.is_cser3_child()
            || ToolOperationPlan::handoff_child_for_descriptor(source, descriptor).ok()? != child
        {
            return None;
        }
        ToolOutcomeVerifier::new(child, epoch).map(|inner| Self {
            inner,
            child_descriptor: Some(descriptor),
        })
    }
}

impl HandoffResolutionVerifier for ToolHandoffResolutionVerifier {
    type Receipt = DurableToolObservation;

    fn identity(&self) -> VerifierIdentity {
        self.inner.identity_for(TOOL_COMMIT_RECEIPT_SCHEMA)
    }

    fn verify_handoff_parent_success(
        &self,
        challenge: &HandoffResolutionChallenge,
        observation: &DurableToolObservation,
    ) -> Result<Digest, VerificationError> {
        if !self.inner.exact_observation(observation)
            || observation.outcome() != ExternalOutcome::Success
            || challenge.effect() != self.inner.plan.effect()
            || challenge.component() != self.inner.plan.component()
            || challenge.domain() != TOOL_DOMAIN
            || challenge.obligation() != TOOL_OBLIGATION_INVOCATION
            || challenge.operation() != self.inner.plan.operation_digest()
            || challenge.expected_verifier() != TOOL_VERIFIER
            || challenge.expected_receipt_schema() != TOOL_COMMIT_RECEIPT_SCHEMA
        {
            return Err(VerificationError::Rejected);
        }
        let descriptor = ToolChildDescriptorVerifier::new(self.inner.plan)
            .ok_or(VerificationError::Rejected)?
            .decode(*observation)
            .map_err(|_| VerificationError::Rejected)?;
        if descriptor != challenge.descriptor() {
            return Err(VerificationError::Rejected);
        }
        Ok(observation.receipt_digest(b"nexus-cser-tool-commit-v1"))
    }
}

impl HandoffChildResolutionVerifier for ToolHandoffResolutionVerifier {
    type Receipt = DurableToolObservation;

    fn identity(&self) -> VerifierIdentity {
        self.inner.identity_for(TOOL_COMMIT_RECEIPT_SCHEMA)
    }

    fn verify_handoff_child_success(
        &self,
        challenge: &HandoffResolutionChallenge,
        observation: &DurableToolObservation,
    ) -> Result<Digest, VerificationError> {
        if self.child_descriptor != Some(challenge.descriptor())
            || !self.inner.exact_observation(observation)
            || observation.outcome() != ExternalOutcome::Success
            || challenge.effect() != self.inner.plan.effect()
            || challenge.component() != self.inner.plan.component()
            || challenge.domain() != TOOL_DOMAIN
            || challenge.obligation() != TOOL_OBLIGATION_INVOCATION
            || challenge.operation() != self.inner.plan.operation_digest()
            || challenge.expected_verifier() != TOOL_VERIFIER
            || challenge.expected_receipt_schema() != TOOL_COMMIT_RECEIPT_SCHEMA
        {
            return Err(VerificationError::Rejected);
        }
        Ok(observation.receipt_digest(b"nexus-cser-tool-commit-v1"))
    }
}

fn decode_core_child_descriptor(
    output: ToolTerminalOutput,
) -> Result<cser_core::ChildDescriptorV1, ToolObservationError> {
    if output.kind() != ToolTerminalOutputKind::ChildDescriptorV1
        || output.bytes().len() != cser_core::CHILD_DESCRIPTOR_V1_WIRE_LEN
    {
        return Err(ToolObservationError::PlanRecordMismatch);
    }
    cser_core::ChildDescriptorV1::decode_wire(output.bytes())
        .map_err(|_| ToolObservationError::PlanRecordMismatch)
}

#[cfg(ktest)]
mod tests {
    use super::*;
    use crate::core_tool_uart::{
        OperationKey, ToolResponse, ToolRunId, ToolTerminalOutput, ToolTerminalRecord,
        ToolV2Identity, terminal_record_for_test,
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
    fn checksum_bound_nonterminal_absent_and_expired_states_remain_distinct() {
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
            Ok(ToolEndpointObservation::Absent),
        );
        assert_eq!(
            UartToolEndpoint::observation(plan, ToolResponse::missing_terminal_for_test(500)),
            Err(ToolTransportError::NoTerminalRecord { status: 500 }),
        );
    }

    #[test]
    fn canonical_core_child_descriptor_wire_is_the_only_accepted_shape() {
        let parent = EffectId::new(RootId::new(9).unwrap(), 2).unwrap();
        let descriptor = cser_core::ChildDescriptorV1 {
            schema: 1,
            sequence: 1,
            parent,
            parent_component: cser_core::TOOL_HANDOFF_COMPONENT,
            route_digest: Digest::new([1; 32]),
            child_kind: cser_core::TOOL_HANDOFF_CHILD_COMPOSITE,
            child_component: cser_core::TOOL_HANDOFF_COMPONENT,
            claim: ClaimId::new(7).unwrap(),
            claim_kind: cser_core::TOOL_CLAIM_OUTCOME_SLOT,
            scope: cser_core::ClaimScope::Logical,
            resource: ResourceId::new(8).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
            input_digest: Digest::new([2; 32]),
            catalog_digest: Digest::new([3; 32]),
        };
        let wire = descriptor.encode_wire();
        assert_eq!(wire.len(), cser_core::CHILD_DESCRIPTOR_V1_WIRE_LEN);
        let output = ToolTerminalOutput::child_descriptor(&wire).unwrap();
        assert_eq!(decode_core_child_descriptor(output), Ok(descriptor));
        let mut altered = wire;
        altered[0] ^= 1;
        assert_eq!(
            decode_core_child_descriptor(ToolTerminalOutput::child_descriptor(&altered).unwrap()),
            Err(ToolObservationError::PlanRecordMismatch),
        );
    }

    #[test]
    fn child_descriptor_verifier_binds_live_terminal_plan_fields() {
        let parent = EffectId::new(RootId::new(21).unwrap(), 2).unwrap();
        let payload = b"handoff-input";
        let catalog = cser_core::tool_dma_catalog().digest();
        let identity = ToolV2Identity::new(
            b"tool",
            ToolRunId::new([3; 16]),
            ToolRunId::new([4; 16]),
            catalog.bytes(),
        )
        .unwrap();
        let route = provider_child_route();
        let plan = ToolOperationPlan::handoff_source(
            [6; 16],
            parent,
            ClaimId::new(7).unwrap(),
            ResourceId::new(8).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            catalog,
            payload,
        )
        .unwrap()
        .bind_cser3(identity);
        assert_eq!(plan.transport_identity(), Some(identity));
        let descriptor = cser_core::ChildDescriptorV1 {
            schema: 1,
            sequence: 1,
            parent,
            parent_component: cser_core::TOOL_HANDOFF_SOURCE_COMPONENT,
            route_digest: route,
            child_kind: cser_core::TOOL_HANDOFF_CHILD_COMPOSITE,
            child_component: cser_core::TOOL_HANDOFF_COMPONENT,
            claim: ClaimId::new(7).unwrap(),
            claim_kind: cser_core::TOOL_CLAIM_OUTCOME_SLOT,
            scope: cser_core::ClaimScope::Logical,
            resource: ResourceId::new(8).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
            input_digest: plan.payload_digest(),
            catalog_digest: catalog,
        };
        let record = ToolTerminalRecord::succeeded_with_output_for_test(
            identity,
            ToolRunId::new([6; 16]),
            OperationKey::new(&plan.operation_key_hex()).unwrap(),
            payload,
            ToolTerminalOutput::child_descriptor(&descriptor.encode_wire()).unwrap(),
        )
        .unwrap();
        let observation = DurableToolObservation::from_terminal_record(plan, record).unwrap();
        let verifier = ToolChildDescriptorVerifier::new(plan).unwrap();
        assert!(
            cser_core::ChildDescriptorVerifier::verify_child_descriptor(
                &verifier,
                descriptor,
                &observation
            )
            .is_ok()
        );
        let mut wrong_route = descriptor;
        wrong_route.route_digest = Digest::new([9; 32]);
        assert!(
            cser_core::ChildDescriptorVerifier::verify_child_descriptor(
                &verifier,
                wrong_route,
                &observation
            )
            .is_err()
        );
        let mut wrong_input = descriptor;
        wrong_input.input_digest = Digest::new([10; 32]);
        assert!(
            cser_core::ChildDescriptorVerifier::verify_child_descriptor(
                &verifier,
                wrong_input,
                &observation
            )
            .is_err()
        );
        let mut wrong_catalog = descriptor;
        wrong_catalog.catalog_digest = Digest::new([11; 32]);
        assert!(
            cser_core::ChildDescriptorVerifier::verify_child_descriptor(
                &verifier,
                wrong_catalog,
                &observation
            )
            .is_err()
        );
    }

    #[test]
    fn cser3_child_plan_is_descriptor_bound_and_requires_output_none() {
        let parent = EffectId::new(RootId::new(31).unwrap(), 2).unwrap();
        let catalog = cser_core::tool_dma_catalog().digest();
        let identity = ToolV2Identity::new(
            b"handoff",
            ToolRunId::new([4; 16]),
            ToolRunId::new([5; 16]),
            catalog.bytes(),
        )
        .unwrap();
        let source = ToolOperationPlan::handoff_source(
            [6; 16],
            parent,
            ClaimId::new(7).unwrap(),
            ResourceId::new(8).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            catalog,
            b"parent-input",
        )
        .unwrap()
        .bind_cser3(identity);
        assert_eq!(source.transport_identity(), Some(identity));
        let descriptor = cser_core::ChildDescriptorV1 {
            schema: 1,
            sequence: 1,
            parent,
            parent_component: cser_core::TOOL_HANDOFF_SOURCE_COMPONENT,
            route_digest: provider_child_route(),
            child_kind: cser_core::TOOL_HANDOFF_CHILD_COMPOSITE,
            child_component: cser_core::TOOL_HANDOFF_COMPONENT,
            claim: ClaimId::new(9).unwrap(),
            claim_kind: cser_core::TOOL_CLAIM_OUTCOME_SLOT,
            scope: cser_core::ClaimScope::Logical,
            resource: ResourceId::new(10).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
            input_digest: source.payload_digest(),
            catalog_digest: catalog,
        };
        let child = ToolOperationPlan::handoff_child_for_descriptor(source, descriptor).unwrap();
        assert!(child.is_cser3_child());
        assert_eq!(child.run_id(), source.run_id());
        assert_eq!(child.effect(), descriptor.child_effect().unwrap());
        assert_eq!(child.payload_digest(), handoff_child_payload(descriptor));
        assert_eq!(
            child.transport_identity().unwrap().effect(),
            handoff_child_transport_effect(identity, source.run_id())
        );
        assert_eq!(
            child.transport_identity(),
            Some(handoff_child_transport_identity(source, identity))
        );
        let terminal = terminal_record_for_test(
            ToolRunId::new(child.run_id()),
            OperationKey::new(&child.operation_key_hex()).unwrap(),
            child.payload(),
        );
        assert!(DurableToolObservation::from_terminal_record(child, terminal).is_ok());
        let output = ToolTerminalOutput::child_descriptor(&descriptor.encode_wire()).unwrap();
        let wrong_output = ToolTerminalRecord::succeeded_with_output_for_test(
            handoff_child_transport_identity(source, identity),
            ToolRunId::new(child.run_id()),
            OperationKey::new(&child.operation_key_hex()).unwrap(),
            child.payload(),
            output,
        )
        .unwrap();
        assert_eq!(
            DurableToolObservation::from_terminal_record(child, wrong_output),
            Err(ToolObservationError::PlanRecordMismatch)
        );
        let mut wrong_descriptor = descriptor;
        wrong_descriptor.parent = EffectId::new(RootId::new(32).unwrap(), 2).unwrap();
        assert_eq!(
            ToolOperationPlan::handoff_child_for_descriptor(source, wrong_descriptor),
            Err(ToolPlanError::InvalidCoordinate)
        );
        assert!(ToolHandoffResolutionVerifier::new(child, 1).is_none());
        assert!(ToolHandoffResolutionVerifier::new_child(child, source, descriptor, 1).is_some());
        assert!(
            ToolHandoffResolutionVerifier::new_child(child, source, wrong_descriptor, 1).is_none()
        );
    }

    #[test]
    fn child_transport_effect_uses_raw_wire_identity_golden() {
        let parent = ToolV2Identity::new(
            b"tool-dma",
            ToolRunId::new([0xbb; 16]),
            ToolRunId::new([0xcc; 16]),
            [0xaa; 32],
        )
        .unwrap();
        assert_eq!(
            handoff_child_transport_effect(parent, [0xdd; 16]).bytes(),
            [
                0x18, 0xf2, 0x28, 0xfd, 0x72, 0xac, 0x7f, 0x08, 0x60, 0x85, 0x49, 0x35, 0x28, 0x69,
                0x8c, 0x05,
            ]
        );
    }
}
