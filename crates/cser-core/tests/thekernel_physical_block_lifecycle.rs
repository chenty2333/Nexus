#[allow(dead_code)]
mod support;

use cser_core::{
    BLOCK_APPLY_RECEIPT_SCHEMA, BLOCK_CLAIM_COMPLETION, BLOCK_CLAIM_DESCRIPTOR, BLOCK_CLAIM_IOVA,
    BLOCK_CLAIM_PINNED_PAGE, BLOCK_CLAIM_QUEUE_SLOT, BLOCK_CLAIM_RECOVERY_DESCRIPTOR,
    BLOCK_CLAIM_RECOVERY_IOVA, BLOCK_CLAIM_RECOVERY_PINNED_PAGE, BLOCK_CLAIM_RECOVERY_QUEUE_SLOT,
    BLOCK_COMMIT_RECEIPT_SCHEMA, BLOCK_COMPLETION_RECEIPT_SCHEMA, BLOCK_DMA_UNMAP_RECEIPT_SCHEMA,
    BLOCK_EVIDENCE_COMPLETION, BLOCK_EVIDENCE_DMA_UNMAPPED, BLOCK_EVIDENCE_IOTLB,
    BLOCK_EVIDENCE_IRQ_DRAINED, BLOCK_EVIDENCE_RESET, BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
    BLOCK_RECOVERY_RECEIPT_SCHEMA, BLOCK_SETTLEMENT_RECEIPT_SCHEMA, BLOCK_VERIFIER,
    BlockUsedCompletionReceipt, BlockUsedCompletionVerifier, Command as AuthorizedCommand,
    CommandRequest as Command, ComponentCommitOperation, ComponentProviderBinding, CoreError,
    DeviceGeneration, EffectId, ExternalOutcome, Freshness, ReceiptSchemaId, ReceiptVerifier,
    ResourceGeneration, RetirementState, THEKERNEL_BLOCK_COMPONENT_COMPLETION,
    THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO, THEKERNEL_BLOCK_COMPONENT_RECOVERY,
    THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE, THEKERNEL_PHYSICAL_BLOCK_IO_RECOVERY_COMPOSITE,
    TransitionOutput, VerificationError, VerifiedObservation, VerifierIdentity,
    thekernel_physical_block_io_catalog,
};
use support::{
    Harness, charge, claim, digest, effect, executor, provider, resource,
    verified_apply_completion, verified_commit_outcome, verified_settlement_ack,
};

const DEVICE_SCOPE: u64 = 901;
const QUEUE_RESOURCE: u64 = 902;
const DESCRIPTOR_RESOURCE: u64 = 903;
const PAGE_RESOURCE: u64 = 904;
const IOVA_RESOURCE: u64 = 905;
const QUEUE_CLAIM: u64 = 910;
const DESCRIPTOR_CLAIM: u64 = 911;
const PAGE_CLAIM: u64 = 912;
const IOVA_CLAIM: u64 = 913;
const NORMAL_COMPLETION_COOKIE: u64 = 77;
const RESET_QUEUE_RESOURCE: u64 = 1_002;
const RESET_DESCRIPTOR_RESOURCE: u64 = 1_003;
const RESET_PAGE_RESOURCE: u64 = 1_004;
const RESET_IOVA_RESOURCE: u64 = 1_005;
const RESET_QUEUE_CLAIM: u64 = 1_010;
const RESET_DESCRIPTOR_CLAIM: u64 = 1_011;
const RESET_PAGE_CLAIM: u64 = 1_012;
const RESET_IOVA_CLAIM: u64 = 1_013;
const RESET_COMPLETION_RESOURCE: u64 = 1_021;
const RESET_COMPLETION_CLAIM: u64 = 1_020;
const REUSED_PAGE_RESOURCE: u64 = 1_904;
const REUSED_IOVA_RESOURCE: u64 = 1_905;
const REUSED_COMPLETION_RESOURCE: u64 = 1_921;
const REUSED_COMPLETION_CLAIM: u64 = 1_920;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockReceipt {
    effect: EffectId,
    claim: cser_core::ClaimId,
    kind: cser_core::EvidenceKindId,
    resource: cser_core::ResourceId,
    resource_generation: ResourceGeneration,
    subject: Freshness,
    subject_binding: cser_core::ExecutorBinding,
    observation: Freshness,
    observation_binding: cser_core::ExecutorBinding,
    queue: cser_core::ResourceId,
    queue_generation: ResourceGeneration,
    request: cser_core::ResourceId,
    request_generation: ResourceGeneration,
    completion_cookie: u64,
    digest: cser_core::Digest,
}

#[derive(Clone, Copy, Debug)]
struct BlockVerifier {
    identity: VerifierIdentity,
    queue: cser_core::ResourceId,
    queue_generation: ResourceGeneration,
    request: cser_core::ResourceId,
    request_generation: ResourceGeneration,
    completion_cookie: u64,
}

impl BlockVerifier {
    fn new(schema: ReceiptSchemaId, queue: u64, request: u64, completion_cookie: u64) -> Self {
        Self {
            identity: VerifierIdentity::new_exact(support::verifier_binding(
                BLOCK_VERIFIER,
                schema,
            )),
            queue: resource(queue),
            queue_generation: ResourceGeneration::new(1).unwrap(),
            request: resource(request),
            request_generation: ResourceGeneration::new(1).unwrap(),
            completion_cookie,
        }
    }
}

impl ReceiptVerifier for BlockVerifier {
    type Receipt = BlockReceipt;

    fn identity(&self) -> VerifierIdentity {
        self.identity
    }

    fn verify(
        &self,
        challenge: &cser_core::EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        if receipt.effect != challenge.effect()
            || receipt.claim != challenge.claim()
            || receipt.kind != challenge.kind()
            || receipt.resource != challenge.resource()
            || receipt.resource_generation != challenge.resource_generation()
            || receipt.subject != challenge.subject()
            || receipt.subject_binding != challenge.subject_binding()
            || receipt.observation_binding != challenge.current_binding()
            || receipt.queue != self.queue
            || receipt.queue_generation != self.queue_generation
            || receipt.request != self.request
            || receipt.request_generation != self.request_generation
            || receipt.digest.is_zero()
        {
            return Err(VerificationError::Rejected);
        }
        if challenge.kind() == BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED
            && receipt.completion_cookie != self.completion_cookie
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new_bound(
            receipt.subject,
            receipt.subject_binding,
            receipt.observation,
            receipt.observation_binding,
            receipt.digest,
        ))
    }
}

fn block_harness() -> Harness {
    Harness::with_catalog(
        thekernel_physical_block_io_catalog(),
        cser_core::CoreLimits::bounded_default(),
    )
}

fn admit(
    harness: &mut Harness,
    effect: EffectId,
    actor: cser_core::ExecutorCoordinate,
    kind: cser_core::CompositeKindId,
    physical_component: cser_core::ComponentId,
) {
    harness
        .tx(Command::AdmitScopedCompositeEffect {
            effect,
            origin: actor,
            kind,
            charge_account: charge(effect.operation().get()),
            bindings: vec![
                ComponentProviderBinding::new(THEKERNEL_BLOCK_COMPONENT_COMPLETION, provider()),
                ComponentProviderBinding::new(physical_component, provider()),
            ],
        })
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn add_claim(
    harness: &mut Harness,
    effect: EffectId,
    actor: cser_core::ExecutorCoordinate,
    component: cser_core::ComponentId,
    claim_id: u64,
    kind: cser_core::ClaimKindId,
    resource_id: u64,
    units: u64,
) {
    harness
        .tx(Command::AddComponentClaim {
            effect,
            component,
            actor,
            claim: claim(claim_id),
            kind,
            scope: cser_core::ClaimScope::Device(
                cser_core::DeviceScopeId::new(DEVICE_SCOPE).unwrap(),
            ),
            resource: resource(resource_id),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units,
        })
        .unwrap();
}

fn add_logical_claim(
    harness: &mut Harness,
    effect: EffectId,
    actor: cser_core::ExecutorCoordinate,
) {
    add_logical_claim_with_ids(harness, effect, actor, 920, 921);
}

fn add_logical_claim_with_ids(
    harness: &mut Harness,
    effect: EffectId,
    actor: cser_core::ExecutorCoordinate,
    claim_id: u64,
    resource_id: u64,
) {
    harness
        .tx(Command::AddComponentClaim {
            effect,
            component: THEKERNEL_BLOCK_COMPONENT_COMPLETION,
            actor,
            claim: claim(claim_id),
            kind: BLOCK_CLAIM_COMPLETION,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(resource_id),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        })
        .unwrap();
}

fn settle_logical_completion(
    harness: &mut Harness,
    effect: EffectId,
    actor: cser_core::ExecutorCoordinate,
) {
    let settlement = match harness.output(Command::ClaimComponentSettlement {
        effect,
        component: THEKERNEL_BLOCK_COMPONENT_COMPLETION,
        claimant: actor,
    }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected block settlement claim, got {other:?}"),
    };
    let settlement = match harness.output(settlement.record_apply_intent(digest(80)).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected block apply intent, got {other:?}"),
    };
    let applied = verified_apply_completion(
        harness,
        &settlement,
        BLOCK_VERIFIER,
        BLOCK_APPLY_RECEIPT_SCHEMA,
        digest(81),
    );
    let settlement = match harness.output(settlement.record_applied(applied).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected block applied claim, got {other:?}"),
    };
    let acknowledgement = verified_settlement_ack(
        harness,
        &settlement,
        BLOCK_VERIFIER,
        BLOCK_SETTLEMENT_RECEIPT_SCHEMA,
        digest(82),
    );
    harness
        .tx(settlement.settle(acknowledgement).unwrap())
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn physical_fixture(
    harness: &mut Harness,
    operation: u64,
    kind: cser_core::CompositeKindId,
    physical_component: cser_core::ComponentId,
    queue_kind: cser_core::ClaimKindId,
    descriptor_kind: cser_core::ClaimKindId,
    page_kind: cser_core::ClaimKindId,
    iova_kind: cser_core::ClaimKindId,
) -> (EffectId, cser_core::ExecutorCoordinate, Freshness) {
    physical_fixture_with_resource_ids(
        harness,
        operation,
        kind,
        physical_component,
        queue_kind,
        descriptor_kind,
        page_kind,
        iova_kind,
        QUEUE_RESOURCE,
        DESCRIPTOR_RESOURCE,
    )
}

#[allow(clippy::too_many_arguments)]
fn physical_fixture_with_resource_ids(
    harness: &mut Harness,
    operation: u64,
    kind: cser_core::CompositeKindId,
    physical_component: cser_core::ComponentId,
    queue_kind: cser_core::ClaimKindId,
    descriptor_kind: cser_core::ClaimKindId,
    page_kind: cser_core::ClaimKindId,
    iova_kind: cser_core::ClaimKindId,
    queue_resource_id: u64,
    descriptor_resource_id: u64,
) -> (EffectId, cser_core::ExecutorCoordinate, Freshness) {
    let effect = effect(operation, 1);
    let actor = executor(operation, 1);
    admit(harness, effect, actor, kind, physical_component);
    add_logical_claim(harness, effect, actor);
    add_claim(
        harness,
        effect,
        actor,
        physical_component,
        QUEUE_CLAIM,
        queue_kind,
        queue_resource_id,
        1,
    );
    add_claim(
        harness,
        effect,
        actor,
        physical_component,
        DESCRIPTOR_CLAIM,
        descriptor_kind,
        descriptor_resource_id,
        1,
    );
    add_claim(
        harness,
        effect,
        actor,
        physical_component,
        PAGE_CLAIM,
        page_kind,
        PAGE_RESOURCE,
        2,
    );
    add_claim(
        harness,
        effect,
        actor,
        physical_component,
        IOVA_CLAIM,
        iova_kind,
        IOVA_RESOURCE,
        1,
    );
    harness
        .tx(Command::PrepareCompositeEffect { effect, actor })
        .unwrap();
    let intents = match harness.output(Command::RecordCompositeCommitIntents {
        effect,
        actor,
        operations: vec![
            ComponentCommitOperation::new(THEKERNEL_BLOCK_COMPONENT_COMPLETION, digest(90)),
            ComponentCommitOperation::new(physical_component, digest(92)),
        ],
    }) {
        TransitionOutput::CompositeCommitIntents(intents) => intents,
        other => panic!("expected block composite commit intents, got {other:?}"),
    };
    for (intent, marker) in intents.into_iter().zip([91_u8, 93_u8]) {
        let outcome = verified_commit_outcome(
            harness,
            &intent,
            BLOCK_VERIFIER,
            BLOCK_COMMIT_RECEIPT_SCHEMA,
            ExternalOutcome::Success,
            digest(marker),
        );
        harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    }
    let initial_evidence = if queue_kind == BLOCK_CLAIM_QUEUE_SLOT {
        BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED
    } else {
        BLOCK_EVIDENCE_RESET
    };
    let subject = harness
        .engine
        .component_evidence_challenge(
            effect,
            physical_component,
            claim(QUEUE_CLAIM),
            initial_evidence,
        )
        .unwrap()
        .subject();
    (effect, actor, subject)
}

fn reused_generation_fixture(
    harness: &mut Harness,
) -> (EffectId, cser_core::ExecutorCoordinate, Freshness) {
    let (old_effect, old_actor, _) = physical_fixture(
        harness,
        931,
        THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
        BLOCK_CLAIM_QUEUE_SLOT,
        BLOCK_CLAIM_DESCRIPTOR,
        BLOCK_CLAIM_PINNED_PAGE,
        BLOCK_CLAIM_IOVA,
    );
    settle_logical_completion(harness, old_effect, old_actor);
    let logical_challenge = harness
        .engine
        .component_evidence_challenge(
            old_effect,
            THEKERNEL_BLOCK_COMPONENT_COMPLETION,
            claim(920),
            BLOCK_EVIDENCE_COMPLETION,
        )
        .unwrap();
    submit_evidence(
        harness,
        old_effect,
        THEKERNEL_BLOCK_COMPONENT_COMPLETION,
        920,
        BLOCK_EVIDENCE_COMPLETION,
        BLOCK_COMPLETION_RECEIPT_SCHEMA,
        logical_challenge.subject(),
        logical_challenge.current_observation(),
        QUEUE_RESOURCE,
        DESCRIPTOR_RESOURCE,
        NORMAL_COMPLETION_COOKIE,
    )
    .unwrap();
    for claim_id in [QUEUE_CLAIM, DESCRIPTOR_CLAIM] {
        let challenge = harness
            .engine
            .component_evidence_challenge(
                old_effect,
                THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
                claim(claim_id),
                BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
            )
            .unwrap();
        submit_evidence(
            harness,
            old_effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            claim_id,
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
            cser_core::BLOCK_RECEIPT_SCHEMA,
            challenge.subject(),
            challenge.current_observation(),
            QUEUE_RESOURCE,
            DESCRIPTOR_RESOURCE,
            NORMAL_COMPLETION_COOKIE,
        )
        .unwrap();
    }
    for (claim_id, resource_id) in [(PAGE_CLAIM, PAGE_RESOURCE), (IOVA_CLAIM, IOVA_RESOURCE)] {
        let challenge = harness
            .engine
            .component_evidence_challenge(
                old_effect,
                THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
                claim(claim_id),
                BLOCK_EVIDENCE_DMA_UNMAPPED,
            )
            .unwrap();
        submit_evidence(
            harness,
            old_effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            claim_id,
            BLOCK_EVIDENCE_DMA_UNMAPPED,
            BLOCK_DMA_UNMAP_RECEIPT_SCHEMA,
            challenge.subject(),
            challenge.current_observation(),
            QUEUE_RESOURCE,
            DESCRIPTOR_RESOURCE,
            NORMAL_COMPLETION_COOKIE,
        )
        .unwrap();
        assert_eq!(
            harness
                .engine
                .check_reusable(resource(resource_id), ResourceGeneration::new(1).unwrap()),
            Ok(())
        );
    }

    let effect = effect(932, 1);
    let actor = executor(932, 1);
    admit(
        harness,
        effect,
        actor,
        THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
    );
    add_logical_claim_with_ids(
        harness,
        effect,
        actor,
        REUSED_COMPLETION_CLAIM,
        REUSED_COMPLETION_RESOURCE,
    );
    for (claim_id, kind, resource_id, contract) in [
        (QUEUE_CLAIM, BLOCK_CLAIM_QUEUE_SLOT, QUEUE_RESOURCE, 201_u8),
        (
            DESCRIPTOR_CLAIM,
            BLOCK_CLAIM_DESCRIPTOR,
            DESCRIPTOR_RESOURCE,
            202_u8,
        ),
    ] {
        let permit = match harness.output(Command::ReserveComponentReuse {
            effect,
            component: THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            actor,
            claim: claim(claim_id),
            kind,
            scope: cser_core::ClaimScope::Device(
                cser_core::DeviceScopeId::new(DEVICE_SCOPE).unwrap(),
            ),
            resource: resource(resource_id),
            expected_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
            reuse_contract: digest(contract),
        }) {
            TransitionOutput::ReusePermit(permit) => permit,
            other => panic!("expected block reuse permit, got {other:?}"),
        };
        harness.tx(permit.activate()).unwrap();
    }
    add_claim(
        harness,
        effect,
        actor,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
        PAGE_CLAIM,
        BLOCK_CLAIM_PINNED_PAGE,
        REUSED_PAGE_RESOURCE,
        2,
    );
    add_claim(
        harness,
        effect,
        actor,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
        IOVA_CLAIM,
        BLOCK_CLAIM_IOVA,
        REUSED_IOVA_RESOURCE,
        1,
    );
    harness
        .tx(Command::PrepareCompositeEffect { effect, actor })
        .unwrap();
    let intents = match harness.output(Command::RecordCompositeCommitIntents {
        effect,
        actor,
        operations: vec![
            ComponentCommitOperation::new(THEKERNEL_BLOCK_COMPONENT_COMPLETION, digest(94)),
            ComponentCommitOperation::new(THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO, digest(96)),
        ],
    }) {
        TransitionOutput::CompositeCommitIntents(intents) => intents,
        other => panic!("expected reused block commit intents, got {other:?}"),
    };
    for (intent, marker) in intents.into_iter().zip([95_u8, 97_u8]) {
        let outcome = verified_commit_outcome(
            harness,
            &intent,
            BLOCK_VERIFIER,
            BLOCK_COMMIT_RECEIPT_SCHEMA,
            ExternalOutcome::Success,
            digest(marker),
        );
        harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    }
    let subject = harness
        .engine
        .component_evidence_challenge(
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            claim(QUEUE_CLAIM),
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        )
        .unwrap()
        .subject();
    (effect, actor, subject)
}

fn advance_device_generation(harness: &mut Harness, operation: u64) {
    let effect = effect(operation, 1);
    let actor = executor(operation, 1);
    admit(
        harness,
        effect,
        actor,
        THEKERNEL_PHYSICAL_BLOCK_IO_RECOVERY_COMPOSITE,
        THEKERNEL_BLOCK_COMPONENT_RECOVERY,
    );
    add_logical_claim_with_ids(
        harness,
        effect,
        actor,
        RESET_COMPLETION_CLAIM,
        RESET_COMPLETION_RESOURCE,
    );
    add_claim(
        harness,
        effect,
        actor,
        THEKERNEL_BLOCK_COMPONENT_RECOVERY,
        RESET_QUEUE_CLAIM,
        BLOCK_CLAIM_RECOVERY_QUEUE_SLOT,
        RESET_QUEUE_RESOURCE,
        1,
    );
    add_claim(
        harness,
        effect,
        actor,
        THEKERNEL_BLOCK_COMPONENT_RECOVERY,
        RESET_DESCRIPTOR_CLAIM,
        BLOCK_CLAIM_RECOVERY_DESCRIPTOR,
        RESET_DESCRIPTOR_RESOURCE,
        1,
    );
    add_claim(
        harness,
        effect,
        actor,
        THEKERNEL_BLOCK_COMPONENT_RECOVERY,
        RESET_PAGE_CLAIM,
        BLOCK_CLAIM_RECOVERY_PINNED_PAGE,
        RESET_PAGE_RESOURCE,
        1,
    );
    add_claim(
        harness,
        effect,
        actor,
        THEKERNEL_BLOCK_COMPONENT_RECOVERY,
        RESET_IOVA_CLAIM,
        BLOCK_CLAIM_RECOVERY_IOVA,
        RESET_IOVA_RESOURCE,
        1,
    );
    harness
        .tx(Command::PrepareCompositeEffect { effect, actor })
        .unwrap();
    let intents = match harness.output(Command::RecordCompositeCommitIntents {
        effect,
        actor,
        operations: vec![
            ComponentCommitOperation::new(THEKERNEL_BLOCK_COMPONENT_COMPLETION, digest(190)),
            ComponentCommitOperation::new(THEKERNEL_BLOCK_COMPONENT_RECOVERY, digest(192)),
        ],
    }) {
        TransitionOutput::CompositeCommitIntents(intents) => intents,
        other => panic!("expected reset composite commit intents, got {other:?}"),
    };
    for (intent, marker) in intents.into_iter().zip([191_u8, 193_u8]) {
        let outcome = verified_commit_outcome(
            harness,
            &intent,
            BLOCK_VERIFIER,
            BLOCK_COMMIT_RECEIPT_SCHEMA,
            ExternalOutcome::Success,
            digest(marker),
        );
        harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    }
    let challenge = harness
        .engine
        .component_evidence_challenge(
            effect,
            THEKERNEL_BLOCK_COMPONENT_RECOVERY,
            claim(RESET_QUEUE_CLAIM),
            BLOCK_EVIDENCE_RESET,
        )
        .unwrap();
    let observation = challenge.current_observation().with_device(
        DeviceGeneration::new(challenge.current_observation().device().get() + 1).unwrap(),
    );
    submit_evidence(
        harness,
        effect,
        THEKERNEL_BLOCK_COMPONENT_RECOVERY,
        RESET_QUEUE_CLAIM,
        BLOCK_EVIDENCE_RESET,
        BLOCK_RECOVERY_RECEIPT_SCHEMA,
        challenge.subject(),
        observation,
        QUEUE_RESOURCE,
        DESCRIPTOR_RESOURCE,
        190,
    )
    .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn evidence_command(
    harness: &Harness,
    effect: EffectId,
    component: cser_core::ComponentId,
    claim_id: u64,
    kind: cser_core::EvidenceKindId,
    schema: ReceiptSchemaId,
    subject: Freshness,
    observation: Freshness,
    queue: u64,
    request: u64,
    cookie: u64,
) -> Result<AuthorizedCommand, CoreError> {
    evidence_command_with_generations(
        harness,
        effect,
        component,
        claim_id,
        kind,
        schema,
        subject,
        observation,
        queue,
        ResourceGeneration::new(1).unwrap(),
        request,
        ResourceGeneration::new(1).unwrap(),
        cookie,
    )
}

#[allow(clippy::too_many_arguments)]
fn evidence_command_with_generations(
    harness: &Harness,
    effect: EffectId,
    component: cser_core::ComponentId,
    claim_id: u64,
    kind: cser_core::EvidenceKindId,
    schema: ReceiptSchemaId,
    subject: Freshness,
    observation: Freshness,
    queue: u64,
    queue_generation: ResourceGeneration,
    request: u64,
    request_generation: ResourceGeneration,
    cookie: u64,
) -> Result<AuthorizedCommand, CoreError> {
    evidence_command_with_verifier_generations(
        harness,
        effect,
        component,
        claim_id,
        kind,
        schema,
        subject,
        observation,
        queue,
        queue_generation,
        request,
        request_generation,
        ResourceGeneration::new(1).unwrap(),
        ResourceGeneration::new(1).unwrap(),
        cookie,
    )
}

#[allow(clippy::too_many_arguments)]
fn evidence_command_with_verifier_generations(
    harness: &Harness,
    effect: EffectId,
    component: cser_core::ComponentId,
    claim_id: u64,
    kind: cser_core::EvidenceKindId,
    schema: ReceiptSchemaId,
    subject: Freshness,
    observation: Freshness,
    queue: u64,
    queue_generation: ResourceGeneration,
    request: u64,
    request_generation: ResourceGeneration,
    verifier_queue_generation: ResourceGeneration,
    verifier_request_generation: ResourceGeneration,
    cookie: u64,
) -> Result<AuthorizedCommand, CoreError> {
    let challenge =
        harness
            .engine
            .component_evidence_challenge(effect, component, claim(claim_id), kind)?;
    if kind == BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED {
        let receipt = BlockUsedCompletionReceipt {
            effect,
            claim: claim(claim_id),
            kind,
            resource: challenge.resource(),
            resource_generation: challenge.resource_generation(),
            subject,
            subject_binding: challenge.subject_binding(),
            observation,
            observation_binding: challenge.current_binding(),
            device_generation: subject.device(),
            queue: resource(queue),
            queue_generation,
            request: resource(request),
            request_generation,
            completion_cookie: cookie,
            digest: digest(cookie as u8),
        };
        let verifier = BlockUsedCompletionVerifier::new(
            VerifierIdentity::new_exact(support::verifier_binding(BLOCK_VERIFIER, schema)),
            resource(QUEUE_RESOURCE),
            verifier_queue_generation,
            resource(DESCRIPTOR_RESOURCE),
            verifier_request_generation,
            NORMAL_COMPLETION_COOKIE,
        );
        return harness
            .engine
            .verify_component_retirement_evidence(
                effect,
                component,
                claim(claim_id),
                kind,
                &verifier,
                &receipt,
            )
            .map(|verified| verified.submit());
    }
    let receipt = BlockReceipt {
        effect,
        claim: claim(claim_id),
        kind,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject,
        subject_binding: challenge.subject_binding(),
        observation,
        observation_binding: challenge.current_binding(),
        queue: resource(queue),
        queue_generation,
        request: resource(request),
        request_generation,
        completion_cookie: cookie,
        digest: digest(cookie as u8),
    };
    let verifier = BlockVerifier::new(
        schema,
        QUEUE_RESOURCE,
        DESCRIPTOR_RESOURCE,
        NORMAL_COMPLETION_COOKIE,
    );
    harness
        .engine
        .verify_component_retirement_evidence(
            effect,
            component,
            claim(claim_id),
            kind,
            &verifier,
            &receipt,
        )
        .map(|verified| verified.submit())
}

#[allow(clippy::too_many_arguments)]
fn submit_evidence(
    harness: &mut Harness,
    effect: EffectId,
    component: cser_core::ComponentId,
    claim_id: u64,
    kind: cser_core::EvidenceKindId,
    schema: ReceiptSchemaId,
    subject: Freshness,
    observation: Freshness,
    queue: u64,
    request: u64,
    cookie: u64,
) -> Result<(), CoreError> {
    let command = evidence_command(
        harness,
        effect,
        component,
        claim_id,
        kind,
        schema,
        subject,
        observation,
        queue,
        request,
        cookie,
    )?;
    harness.tx(command).map(|_| ())
}

#[test]
fn normal_used_completion_requires_exact_same_generation_and_logical_completion_precedes_retirement()
 {
    let mut harness = block_harness();
    let (effect, actor, subject) = physical_fixture(
        &mut harness,
        930,
        THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
        BLOCK_CLAIM_QUEUE_SLOT,
        BLOCK_CLAIM_DESCRIPTOR,
        BLOCK_CLAIM_PINNED_PAGE,
        BLOCK_CLAIM_IOVA,
    );
    settle_logical_completion(&mut harness, effect, actor);
    let logical_observation = harness
        .engine
        .component_evidence_challenge(
            effect,
            THEKERNEL_BLOCK_COMPONENT_COMPLETION,
            claim(920),
            BLOCK_EVIDENCE_COMPLETION,
        )
        .unwrap();
    submit_evidence(
        &mut harness,
        effect,
        THEKERNEL_BLOCK_COMPONENT_COMPLETION,
        920,
        BLOCK_EVIDENCE_COMPLETION,
        BLOCK_COMPLETION_RECEIPT_SCHEMA,
        logical_observation.subject(),
        logical_observation.current_observation(),
        QUEUE_RESOURCE,
        DESCRIPTOR_RESOURCE,
        77,
    )
    .unwrap();
    assert_eq!(
        harness
            .engine
            .component(effect, THEKERNEL_BLOCK_COMPONENT_COMPLETION)
            .unwrap()
            .retirement,
        RetirementState::Retired
    );
    assert_eq!(
        harness
            .engine
            .component(effect, THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO)
            .unwrap()
            .retirement,
        RetirementState::RetirementPending
    );

    let queue_challenge = harness
        .engine
        .component_evidence_challenge(
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            claim(QUEUE_CLAIM),
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        )
        .unwrap();
    assert_eq!(
        evidence_command(
            &harness,
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            QUEUE_CLAIM,
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
            cser_core::BLOCK_RECEIPT_SCHEMA,
            queue_challenge.subject(),
            queue_challenge.current_observation(),
            QUEUE_RESOURCE + 1,
            DESCRIPTOR_RESOURCE,
            77,
        ),
        Err(CoreError::VerificationFailed)
    );
    assert_eq!(
        evidence_command(
            &harness,
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            QUEUE_CLAIM,
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
            cser_core::BLOCK_RECEIPT_SCHEMA,
            queue_challenge.subject(),
            queue_challenge.current_observation(),
            QUEUE_RESOURCE,
            DESCRIPTOR_RESOURCE,
            78,
        ),
        Err(CoreError::VerificationFailed)
    );
    assert_eq!(
        evidence_command_with_generations(
            &harness,
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            QUEUE_CLAIM,
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
            cser_core::BLOCK_RECEIPT_SCHEMA,
            queue_challenge.subject(),
            queue_challenge.current_observation(),
            QUEUE_RESOURCE,
            ResourceGeneration::new(2).unwrap(),
            DESCRIPTOR_RESOURCE,
            ResourceGeneration::new(1).unwrap(),
            77,
        ),
        Err(CoreError::VerificationFailed)
    );
    assert_eq!(
        evidence_command_with_generations(
            &harness,
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            QUEUE_CLAIM,
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
            cser_core::BLOCK_RECEIPT_SCHEMA,
            queue_challenge.subject(),
            queue_challenge.current_observation(),
            QUEUE_RESOURCE,
            ResourceGeneration::new(1).unwrap(),
            DESCRIPTOR_RESOURCE,
            ResourceGeneration::new(2).unwrap(),
            77,
        ),
        Err(CoreError::VerificationFailed)
    );
    let stale_observation = queue_challenge
        .current_observation()
        .with_device(DeviceGeneration::new(2).unwrap());
    assert_eq!(
        evidence_command(
            &harness,
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            QUEUE_CLAIM,
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
            cser_core::BLOCK_RECEIPT_SCHEMA,
            queue_challenge.subject(),
            stale_observation,
            QUEUE_RESOURCE,
            DESCRIPTOR_RESOURCE,
            77,
        )
        .and_then(|command| harness.tx(command).map(|_| ())),
        Err(CoreError::VerificationFailed)
    );
    assert_eq!(
        harness.engine.check_reusable(
            resource(QUEUE_RESOURCE),
            ResourceGeneration::new(1).unwrap()
        ),
        Err(CoreError::ResourceRetained)
    );

    submit_evidence(
        &mut harness,
        effect,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
        QUEUE_CLAIM,
        BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        cser_core::BLOCK_RECEIPT_SCHEMA,
        queue_challenge.subject(),
        queue_challenge.current_observation(),
        QUEUE_RESOURCE,
        DESCRIPTOR_RESOURCE,
        77,
    )
    .unwrap();
    let descriptor_challenge = harness
        .engine
        .component_evidence_challenge(
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            claim(DESCRIPTOR_CLAIM),
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        )
        .unwrap();
    submit_evidence(
        &mut harness,
        effect,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
        DESCRIPTOR_CLAIM,
        BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        cser_core::BLOCK_RECEIPT_SCHEMA,
        descriptor_challenge.subject(),
        descriptor_challenge.current_observation(),
        QUEUE_RESOURCE,
        DESCRIPTOR_RESOURCE,
        77,
    )
    .unwrap();
    for (claim_id, resource_id) in [(PAGE_CLAIM, PAGE_RESOURCE), (IOVA_CLAIM, IOVA_RESOURCE)] {
        let challenge = harness
            .engine
            .component_evidence_challenge(
                effect,
                THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
                claim(claim_id),
                BLOCK_EVIDENCE_DMA_UNMAPPED,
            )
            .unwrap();
        submit_evidence(
            &mut harness,
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            claim_id,
            BLOCK_EVIDENCE_DMA_UNMAPPED,
            BLOCK_DMA_UNMAP_RECEIPT_SCHEMA,
            challenge.subject(),
            challenge.current_observation(),
            QUEUE_RESOURCE,
            DESCRIPTOR_RESOURCE,
            77,
        )
        .unwrap();
        assert_eq!(
            harness
                .engine
                .check_reusable(resource(resource_id), ResourceGeneration::new(1).unwrap()),
            Ok(())
        );
    }
    assert_eq!(
        harness
            .engine
            .component(effect, THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO)
            .unwrap()
            .retirement,
        RetirementState::Retired
    );
    assert_eq!(subject.device().get(), 1);
}

#[test]
fn used_completion_rejects_queue_and_descriptor_identity_swaps() {
    let mut harness = block_harness();
    let (effect, actor, _subject) = physical_fixture_with_resource_ids(
        &mut harness,
        933,
        THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
        BLOCK_CLAIM_QUEUE_SLOT,
        BLOCK_CLAIM_DESCRIPTOR,
        BLOCK_CLAIM_PINNED_PAGE,
        BLOCK_CLAIM_IOVA,
        DESCRIPTOR_RESOURCE,
        QUEUE_RESOURCE,
    );
    settle_logical_completion(&mut harness, effect, actor);
    let logical_challenge = harness
        .engine
        .component_evidence_challenge(
            effect,
            THEKERNEL_BLOCK_COMPONENT_COMPLETION,
            claim(920),
            BLOCK_EVIDENCE_COMPLETION,
        )
        .unwrap();
    submit_evidence(
        &mut harness,
        effect,
        THEKERNEL_BLOCK_COMPONENT_COMPLETION,
        920,
        BLOCK_EVIDENCE_COMPLETION,
        BLOCK_COMPLETION_RECEIPT_SCHEMA,
        logical_challenge.subject(),
        logical_challenge.current_observation(),
        QUEUE_RESOURCE,
        DESCRIPTOR_RESOURCE,
        NORMAL_COMPLETION_COOKIE,
    )
    .unwrap();

    for claim_id in [QUEUE_CLAIM, DESCRIPTOR_CLAIM] {
        let challenge = harness
            .engine
            .component_evidence_challenge(
                effect,
                THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
                claim(claim_id),
                BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
            )
            .unwrap();
        assert_eq!(
            evidence_command(
                &harness,
                effect,
                THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
                claim_id,
                BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
                cser_core::BLOCK_RECEIPT_SCHEMA,
                challenge.subject(),
                challenge.current_observation(),
                QUEUE_RESOURCE,
                DESCRIPTOR_RESOURCE,
                NORMAL_COMPLETION_COOKIE,
            ),
            Err(CoreError::VerificationFailed)
        );
    }
}

#[test]
fn used_completion_binds_claim_generation_to_its_tuple_member() {
    let mut harness = block_harness();
    let (effect, actor, _subject) = reused_generation_fixture(&mut harness);
    settle_logical_completion(&mut harness, effect, actor);

    let logical_challenge = harness
        .engine
        .component_evidence_challenge(
            effect,
            THEKERNEL_BLOCK_COMPONENT_COMPLETION,
            claim(REUSED_COMPLETION_CLAIM),
            BLOCK_EVIDENCE_COMPLETION,
        )
        .unwrap();
    submit_evidence(
        &mut harness,
        effect,
        THEKERNEL_BLOCK_COMPONENT_COMPLETION,
        REUSED_COMPLETION_CLAIM,
        BLOCK_EVIDENCE_COMPLETION,
        BLOCK_COMPLETION_RECEIPT_SCHEMA,
        logical_challenge.subject(),
        logical_challenge.current_observation(),
        QUEUE_RESOURCE,
        DESCRIPTOR_RESOURCE,
        NORMAL_COMPLETION_COOKIE,
    )
    .unwrap();

    let queue_challenge = harness
        .engine
        .component_evidence_challenge(
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            claim(QUEUE_CLAIM),
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        )
        .unwrap();
    assert_eq!(
        evidence_command_with_verifier_generations(
            &harness,
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            QUEUE_CLAIM,
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
            cser_core::BLOCK_RECEIPT_SCHEMA,
            queue_challenge.subject(),
            queue_challenge.current_observation(),
            QUEUE_RESOURCE,
            ResourceGeneration::new(1).unwrap(),
            DESCRIPTOR_RESOURCE,
            ResourceGeneration::new(1).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            NORMAL_COMPLETION_COOKIE,
        ),
        Err(CoreError::VerificationFailed)
    );
    let queue_completion = evidence_command_with_verifier_generations(
        &harness,
        effect,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
        QUEUE_CLAIM,
        BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        cser_core::BLOCK_RECEIPT_SCHEMA,
        queue_challenge.subject(),
        queue_challenge.current_observation(),
        QUEUE_RESOURCE,
        ResourceGeneration::new(2).unwrap(),
        DESCRIPTOR_RESOURCE,
        ResourceGeneration::new(1).unwrap(),
        ResourceGeneration::new(2).unwrap(),
        ResourceGeneration::new(1).unwrap(),
        NORMAL_COMPLETION_COOKIE,
    )
    .unwrap();
    harness.tx(queue_completion).unwrap();

    let descriptor_challenge = harness
        .engine
        .component_evidence_challenge(
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            claim(DESCRIPTOR_CLAIM),
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        )
        .unwrap();
    assert_eq!(
        evidence_command_with_verifier_generations(
            &harness,
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            DESCRIPTOR_CLAIM,
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
            cser_core::BLOCK_RECEIPT_SCHEMA,
            descriptor_challenge.subject(),
            descriptor_challenge.current_observation(),
            QUEUE_RESOURCE,
            ResourceGeneration::new(1).unwrap(),
            DESCRIPTOR_RESOURCE,
            ResourceGeneration::new(1).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            NORMAL_COMPLETION_COOKIE,
        ),
        Err(CoreError::VerificationFailed)
    );
    let descriptor_completion = evidence_command_with_verifier_generations(
        &harness,
        effect,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
        DESCRIPTOR_CLAIM,
        BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        cser_core::BLOCK_RECEIPT_SCHEMA,
        descriptor_challenge.subject(),
        descriptor_challenge.current_observation(),
        QUEUE_RESOURCE,
        ResourceGeneration::new(1).unwrap(),
        DESCRIPTOR_RESOURCE,
        ResourceGeneration::new(2).unwrap(),
        ResourceGeneration::new(1).unwrap(),
        ResourceGeneration::new(2).unwrap(),
        NORMAL_COMPLETION_COOKIE,
    )
    .unwrap();
    harness.tx(descriptor_completion).unwrap();
}

#[test]
fn stale_old_completion_with_new_active_observation_is_rejected() {
    let mut harness = block_harness();
    let (effect, actor, enrolled) = physical_fixture(
        &mut harness,
        935,
        THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
        BLOCK_CLAIM_QUEUE_SLOT,
        BLOCK_CLAIM_DESCRIPTOR,
        BLOCK_CLAIM_PINNED_PAGE,
        BLOCK_CLAIM_IOVA,
    );
    settle_logical_completion(&mut harness, effect, actor);
    let logical_challenge = harness
        .engine
        .component_evidence_challenge(
            effect,
            THEKERNEL_BLOCK_COMPONENT_COMPLETION,
            claim(920),
            BLOCK_EVIDENCE_COMPLETION,
        )
        .unwrap();
    submit_evidence(
        &mut harness,
        effect,
        THEKERNEL_BLOCK_COMPONENT_COMPLETION,
        920,
        BLOCK_EVIDENCE_COMPLETION,
        BLOCK_COMPLETION_RECEIPT_SCHEMA,
        logical_challenge.subject(),
        logical_challenge.current_observation(),
        QUEUE_RESOURCE,
        DESCRIPTOR_RESOURCE,
        NORMAL_COMPLETION_COOKIE,
    )
    .unwrap();
    advance_device_generation(&mut harness, 936);

    let queue_challenge = harness
        .engine
        .component_evidence_challenge(
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            claim(QUEUE_CLAIM),
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        )
        .unwrap();
    assert_eq!(enrolled.device().get(), 1);
    assert_eq!(queue_challenge.subject().device().get(), 1);
    assert_eq!(queue_challenge.current_observation().device().get(), 2);
    assert_eq!(
        evidence_command(
            &harness,
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            QUEUE_CLAIM,
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
            cser_core::BLOCK_RECEIPT_SCHEMA,
            queue_challenge.subject(),
            queue_challenge.current_observation(),
            QUEUE_RESOURCE,
            DESCRIPTOR_RESOURCE,
            NORMAL_COMPLETION_COOKIE,
        ),
        Err(CoreError::VerificationFailed)
    );
    assert_eq!(
        harness.engine.check_reusable(
            resource(QUEUE_RESOURCE),
            ResourceGeneration::new(1).unwrap()
        ),
        Err(CoreError::ResourceRetained)
    );
}

#[test]
fn recovery_retains_each_claim_until_its_reset_conjunct_is_complete() {
    let mut harness = block_harness();
    let (effect, _actor, subject) = physical_fixture(
        &mut harness,
        940,
        THEKERNEL_PHYSICAL_BLOCK_IO_RECOVERY_COMPOSITE,
        THEKERNEL_BLOCK_COMPONENT_RECOVERY,
        BLOCK_CLAIM_RECOVERY_QUEUE_SLOT,
        BLOCK_CLAIM_RECOVERY_DESCRIPTOR,
        BLOCK_CLAIM_RECOVERY_PINNED_PAGE,
        BLOCK_CLAIM_RECOVERY_IOVA,
    );
    let component = THEKERNEL_BLOCK_COMPONENT_RECOVERY;

    let reset_claims = [QUEUE_CLAIM, DESCRIPTOR_CLAIM, PAGE_CLAIM, IOVA_CLAIM];
    for (offset, claim_id) in reset_claims.into_iter().enumerate() {
        let challenge = harness
            .engine
            .component_evidence_challenge(effect, component, claim(claim_id), BLOCK_EVIDENCE_RESET)
            .unwrap();
        let current = challenge.current_observation();
        let observation =
            current.with_device(DeviceGeneration::new(current.device().get() + 1).unwrap());
        submit_evidence(
            &mut harness,
            effect,
            component,
            claim_id,
            BLOCK_EVIDENCE_RESET,
            BLOCK_RECOVERY_RECEIPT_SCHEMA,
            challenge.subject(),
            observation,
            QUEUE_RESOURCE,
            DESCRIPTOR_RESOURCE,
            90 + offset as u64,
        )
        .unwrap();
        let resource_id = [
            QUEUE_RESOURCE,
            DESCRIPTOR_RESOURCE,
            PAGE_RESOURCE,
            IOVA_RESOURCE,
        ][offset];
        assert_eq!(
            harness
                .engine
                .check_reusable(resource(resource_id), ResourceGeneration::new(1).unwrap()),
            Err(CoreError::ResourceRetained)
        );
    }

    for (claim_id, terminal, resource_id) in [
        (QUEUE_CLAIM, BLOCK_EVIDENCE_IRQ_DRAINED, QUEUE_RESOURCE),
        (
            DESCRIPTOR_CLAIM,
            BLOCK_EVIDENCE_IRQ_DRAINED,
            DESCRIPTOR_RESOURCE,
        ),
        (PAGE_CLAIM, BLOCK_EVIDENCE_IOTLB, PAGE_RESOURCE),
        (IOVA_CLAIM, BLOCK_EVIDENCE_IOTLB, IOVA_RESOURCE),
    ] {
        let challenge = harness
            .engine
            .component_evidence_challenge(effect, component, claim(claim_id), terminal)
            .unwrap();
        let result = submit_evidence(
            &mut harness,
            effect,
            component,
            claim_id,
            terminal,
            BLOCK_RECOVERY_RECEIPT_SCHEMA,
            challenge.subject(),
            challenge.current_observation(),
            QUEUE_RESOURCE,
            DESCRIPTOR_RESOURCE,
            120 + claim_id,
        );
        assert!(
            result.is_ok(),
            "terminal recovery evidence must be accepted"
        );
        assert_eq!(
            harness
                .engine
                .check_reusable(resource(resource_id), ResourceGeneration::new(1).unwrap()),
            Ok(())
        );
    }
    assert_eq!(
        harness
            .engine
            .component(effect, component)
            .unwrap()
            .retirement,
        RetirementState::Retired
    );
    assert!(
        harness
            .engine
            .device_generation(cser_core::DeviceScopeId::new(DEVICE_SCOPE).unwrap())
            .unwrap()
            .get()
            > subject.device().get()
    );
}

#[test]
fn a_queue_generation_reuse_is_rejected_before_retirement_and_allowed_after_it() {
    let mut harness = block_harness();
    let (effect, _actor, subject) = physical_fixture(
        &mut harness,
        950,
        THEKERNEL_PHYSICAL_BLOCK_IO_COMPOSITE,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
        BLOCK_CLAIM_QUEUE_SLOT,
        BLOCK_CLAIM_DESCRIPTOR,
        BLOCK_CLAIM_PINNED_PAGE,
        BLOCK_CLAIM_IOVA,
    );
    assert_eq!(
        harness.engine.check_reusable(
            resource(QUEUE_RESOURCE),
            ResourceGeneration::new(1).unwrap()
        ),
        Err(CoreError::ResourceRetained)
    );
    let queue_challenge = harness
        .engine
        .component_evidence_challenge(
            effect,
            THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
            claim(QUEUE_CLAIM),
            BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        )
        .unwrap();
    submit_evidence(
        &mut harness,
        effect,
        THEKERNEL_BLOCK_COMPONENT_PHYSICAL_IO,
        QUEUE_CLAIM,
        BLOCK_EVIDENCE_USED_COMPLETION_QUIESCED,
        cser_core::BLOCK_RECEIPT_SCHEMA,
        subject,
        queue_challenge.current_observation(),
        QUEUE_RESOURCE,
        DESCRIPTOR_RESOURCE,
        77,
    )
    .unwrap();
    assert_eq!(
        harness.engine.check_reusable(
            resource(QUEUE_RESOURCE),
            ResourceGeneration::new(1).unwrap()
        ),
        Ok(())
    );
}
