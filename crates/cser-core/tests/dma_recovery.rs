#[allow(dead_code)]
mod support;

use cser_core::{
    AGENT_COMPONENT_DMA, AuthorityState, CREDIT_IOVA, CREDIT_PINNED_PAGE, CREDIT_QUEUE_SLOT,
    CatalogSet, Command as AuthorizedCommand, CommandRequest as Command, CommitState,
    ComponentProviderBinding, CoreError, CoreLimits, DEVICE_CLAIM_IOVA, DEVICE_CLAIM_PINNED_PAGE,
    DEVICE_CLAIM_QUEUE_SLOT, DEVICE_DOMAIN, DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_IRQ_DRAINED,
    DEVICE_EVIDENCE_RESET, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, DMA_ARENA_REUSE_COMPOSITE,
    DeviceGeneration, Engine, EvidenceKindId, ExecutorCoordinate, ExternalOutcome, Freshness,
    RecoveryAnchor, RetirementState, TransitionOutput, standard_catalog,
};
use support::{
    ExactTestVerifier, Harness, TestReceipt, charge, claim, digest, effect, executor,
    fence_and_rebind, freshness, provider, recovery_anchor, resource, verified_commit_outcome,
};

const QUEUE_CLAIM: u64 = 101;
const PAGE_CLAIM: u64 = 102;
const IOVA_CLAIM: u64 = 103;
const QUEUE_RESOURCE: u64 = 201;
const PAGE_RESOURCE: u64 = 202;
const IOVA_RESOURCE: u64 = 203;

#[derive(Clone, Copy)]
struct DmaClaimRequest {
    claim_value: u64,
    kind: cser_core::ClaimKindId,
    scope_value: u64,
    resource_value: u64,
    units: u64,
}

fn anchor(engine: &Engine, committed: Freshness, next: Freshness) -> RecoveryAnchor {
    recovery_anchor(
        standard_catalog_set().digest(),
        committed,
        next,
        engine.revision(),
        engine.head(),
        engine.projection_digest(),
    )
}

fn standard_catalog_set() -> CatalogSet {
    CatalogSet::new(&[standard_catalog()]).unwrap()
}

fn dma_retained_units(harness: &Harness, account_value: u64) -> u64 {
    [CREDIT_QUEUE_SLOT, CREDIT_PINNED_PAGE, CREDIT_IOVA]
        .into_iter()
        .map(|class| {
            harness
                .engine
                .charge(charge(account_value), class)
                .retained_units
        })
        .sum()
}

fn admit_dma(
    harness: &mut Harness,
    effect: cser_core::EffectId,
    origin: ExecutorCoordinate,
    account_value: u64,
) {
    admit_dma_at(harness, effect, origin, account_value);
}

fn admit_dma_at(
    harness: &mut Harness,
    effect: cser_core::EffectId,
    origin: ExecutorCoordinate,
    account_value: u64,
) {
    harness
        .tx(Command::AdmitScopedCompositeEffect {
            effect,
            origin,
            kind: DMA_ARENA_REUSE_COMPOSITE,
            charge_account: charge(account_value),
            bindings: vec![ComponentProviderBinding::new(
                AGENT_COMPONENT_DMA,
                provider(),
            )],
        })
        .unwrap();
}

fn add_dma_claim(
    harness: &mut Harness,
    effect: cser_core::EffectId,
    actor: ExecutorCoordinate,
    request: DmaClaimRequest,
) -> Result<(), CoreError> {
    add_dma_claim_at(harness, effect, actor, request)
}

fn add_dma_claim_at(
    harness: &mut Harness,
    effect: cser_core::EffectId,
    actor: ExecutorCoordinate,
    request: DmaClaimRequest,
) -> Result<(), CoreError> {
    harness
        .tx(Command::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_DMA,
            actor,
            claim: claim(request.claim_value),
            kind: request.kind,
            scope: cser_core::ClaimScope::Device(
                cser_core::DeviceScopeId::new(request.scope_value).unwrap(),
            ),
            resource: resource(request.resource_value),
            resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
            units: request.units,
        })
        .map(|_| ())
}

#[test]
fn replay_exposes_exact_retained_claims_without_an_adapter_side_tombstone_index() {
    let mut harness = Harness::standard();
    let (effect, _origin, _subject) = committed_dma(&mut harness, 91, 91);

    let claims = harness
        .engine
        .component_claims(effect, AGENT_COMPONENT_DMA)
        .unwrap();
    assert_eq!(claims.len(), 3);
    assert_eq!(
        claims
            .iter()
            .map(|projection| projection.claim.get())
            .collect::<Vec<_>>(),
        vec![QUEUE_CLAIM, PAGE_CLAIM, IOVA_CLAIM]
    );
    for projection in &claims {
        assert_eq!(projection.effect, effect);
        assert_eq!(projection.domain, DEVICE_DOMAIN);
        assert_eq!(
            projection.scope,
            cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap())
        );
        assert_eq!(projection.resource_generation.get(), 1);
        assert!(!projection.retired);
    }

    let report = Engine::recover(
        standard_catalog_set(),
        CoreLimits::bounded_default(),
        anchor(
            &harness.engine,
            freshness(1, 1, 1, 1),
            freshness(2, 1, 2, 2),
        ),
        &harness.journal,
    )
    .unwrap();
    let recovered = report.into_engine();
    assert_eq!(
        recovered
            .component_claims(effect, AGENT_COMPONENT_DMA)
            .unwrap(),
        claims
    );
    assert_eq!(
        recovered.retained_component_claims(),
        claims
            .iter()
            .filter(|claim| !claim.retired)
            .cloned()
            .collect::<Vec<_>>()
    );
    assert!(recovered.pressure().quarantined);
}

fn registered_dma(
    harness: &mut Harness,
    operation_value: u64,
) -> (cser_core::EffectId, ExecutorCoordinate) {
    let effect = effect(operation_value, 1);
    let origin = executor(operation_value, 1);
    admit_dma(harness, effect, origin, operation_value);
    (effect, origin)
}

fn committed_dma(
    harness: &mut Harness,
    operation_value: u64,
    account_value: u64,
) -> (cser_core::EffectId, ExecutorCoordinate, Freshness) {
    committed_dma_with_resource_offset(harness, operation_value, account_value, 0)
}

fn committed_dma_with_resource_offset(
    harness: &mut Harness,
    operation_value: u64,
    account_value: u64,
    resource_offset: u64,
) -> (cser_core::EffectId, ExecutorCoordinate, Freshness) {
    let effect = effect(operation_value, 1);
    let origin = executor(operation_value, 1);
    admit_dma(harness, effect, origin, account_value);
    for (claim_value, kind, resource_value, units) in [
        (QUEUE_CLAIM, DEVICE_CLAIM_QUEUE_SLOT, QUEUE_RESOURCE, 1),
        (PAGE_CLAIM, DEVICE_CLAIM_PINNED_PAGE, PAGE_RESOURCE, 4),
        (IOVA_CLAIM, DEVICE_CLAIM_IOVA, IOVA_RESOURCE, 2),
    ] {
        harness
            .tx(Command::AddComponentClaim {
                effect,
                component: AGENT_COMPONENT_DMA,
                actor: origin,
                claim: claim(claim_value),
                kind,
                scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
                resource: resource(resource_value + resource_offset),
                resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
                units,
            })
            .unwrap();
    }
    harness
        .tx(Command::PrepareCompositeEffect {
            effect,
            actor: origin,
        })
        .unwrap();
    let intent = match harness.output(Command::RecordComponentCommitIntent {
        effect,
        component: AGENT_COMPONENT_DMA,
        actor: origin,
        operation: digest(1),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected DMA commit intent, got {other:?}"),
    };
    let outcome = verified_commit_outcome(
        harness,
        &intent,
        cser_core::DEVICE_VERIFIER,
        cser_core::DEVICE_COMMIT_RECEIPT_SCHEMA,
        ExternalOutcome::Success,
        digest(2),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    let enrolled_freshness = harness
        .engine
        .component_evidence_challenge(
            effect,
            AGENT_COMPONENT_DMA,
            claim(QUEUE_CLAIM),
            DEVICE_EVIDENCE_RESET,
        )
        .unwrap()
        .subject();
    (effect, origin, enrolled_freshness)
}

fn verified_evidence_command(
    harness: &Harness,
    effect: cser_core::EffectId,
    claim_value: u64,
    subject: Freshness,
    kind: cser_core::EvidenceKindId,
    digest_value: u8,
) -> Result<AuthorizedCommand, CoreError> {
    let challenge = harness.engine.component_evidence_challenge(
        effect,
        AGENT_COMPONENT_DMA,
        claim(claim_value),
        kind,
    )?;
    let current = challenge.current_observation();
    let observation = if kind == DEVICE_EVIDENCE_RESET && current.device() == subject.device() {
        Freshness::new(
            current.boot(),
            current.registry(),
            DeviceGeneration::new(current.device().get() + 1).unwrap(),
            current.journal(),
        )
    } else {
        current
    };
    verified_evidence_command_at(
        harness,
        effect,
        claim_value,
        subject,
        kind,
        observation,
        digest_value,
    )
}

fn verified_evidence_command_at(
    harness: &Harness,
    effect: cser_core::EffectId,
    claim_value: u64,
    subject: Freshness,
    kind: cser_core::EvidenceKindId,
    observation: Freshness,
    digest_value: u8,
) -> Result<AuthorizedCommand, CoreError> {
    let challenge = harness.engine.component_evidence_challenge(
        effect,
        AGENT_COMPONENT_DMA,
        claim(claim_value),
        kind,
    )?;
    let receipt = TestReceipt {
        effect,
        claim: claim(claim_value),
        kind,
        subject,
        subject_binding: challenge.subject_binding(),
        observation,
        observation_binding: challenge.current_binding(),
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        digest: digest(digest_value),
    };
    let verifier =
        ExactTestVerifier::new(cser_core::DEVICE_VERIFIER, cser_core::DEVICE_RECEIPT_SCHEMA);
    harness
        .engine
        .verify_component_retirement_evidence(
            effect,
            AGENT_COMPONENT_DMA,
            claim(claim_value),
            kind,
            &verifier,
            &receipt,
        )
        .map(|verified| verified.submit())
}

fn submit(
    harness: &mut Harness,
    effect: cser_core::EffectId,
    subject: Freshness,
    claim_value: u64,
    kind: cser_core::EvidenceKindId,
    digest_value: u8,
) -> Result<(), CoreError> {
    let command =
        verified_evidence_command(harness, effect, claim_value, subject, kind, digest_value)?;
    harness.tx(command).map(|_| ())
}

#[test]
fn queue_page_and_iova_require_their_exact_retirement_conjunctions() {
    let mut harness = Harness::standard();
    let (effect, origin, subject) = committed_dma(&mut harness, 10, 10);
    harness
        .tx(Command::FenceExecutor {
            operation: effect.operation(),
            crashed: origin,
        })
        .unwrap();

    let component = harness
        .engine
        .component(effect, AGENT_COMPONENT_DMA)
        .unwrap();
    assert_eq!(component.commit, CommitState::Committed);
    assert_eq!(component.retirement, RetirementState::RetirementPending);
    assert_eq!(component.retained_claims, 3);
    assert_eq!(dma_retained_units(&harness, 10), 7);
    for resource_value in [QUEUE_RESOURCE, PAGE_RESOURCE, IOVA_RESOURCE] {
        assert_eq!(
            harness.engine.check_reusable(
                resource(resource_value),
                cser_core::ResourceGeneration::new(1).unwrap()
            ),
            Err(CoreError::ResourceRetained)
        );
    }
    let before = harness.engine.projection_digest();
    assert_eq!(
        submit(
            &mut harness,
            effect,
            subject,
            QUEUE_CLAIM,
            DEVICE_EVIDENCE_IRQ_DRAINED,
            10,
        ),
        Err(CoreError::EvidenceOutOfOrder)
    );
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(
        harness.engine.check_reusable(
            resource(QUEUE_RESOURCE),
            cser_core::ResourceGeneration::new(1).unwrap()
        ),
        Err(CoreError::ResourceRetained)
    );

    submit(
        &mut harness,
        effect,
        subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_RESET,
        11,
    )
    .unwrap();
    let before = harness.engine.projection_digest();
    assert_eq!(
        submit(
            &mut harness,
            effect,
            subject,
            QUEUE_CLAIM,
            DEVICE_EVIDENCE_RESET,
            12,
        ),
        Err(CoreError::DuplicateEvidence)
    );
    assert_eq!(harness.engine.projection_digest(), before);

    submit(
        &mut harness,
        effect,
        subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_IRQ_DRAINED,
        13,
    )
    .unwrap();
    assert_eq!(
        harness.engine.check_reusable(
            resource(QUEUE_RESOURCE),
            cser_core::ResourceGeneration::new(1).unwrap()
        ),
        Ok(())
    );
    assert_eq!(dma_retained_units(&harness, 10), 6);

    for (claim_value, resource_value, reset_digest, terminal_digest) in [
        (PAGE_CLAIM, PAGE_RESOURCE, 14, 15),
        (IOVA_CLAIM, IOVA_RESOURCE, 16, 17),
    ] {
        let before = harness.engine.projection_digest();
        assert_eq!(
            submit(
                &mut harness,
                effect,
                subject,
                claim_value,
                DEVICE_EVIDENCE_IOTLB,
                terminal_digest,
            ),
            Err(CoreError::EvidenceOutOfOrder)
        );
        assert_eq!(harness.engine.projection_digest(), before);
        submit(
            &mut harness,
            effect,
            subject,
            claim_value,
            DEVICE_EVIDENCE_RESET,
            reset_digest,
        )
        .unwrap();
        submit(
            &mut harness,
            effect,
            subject,
            claim_value,
            DEVICE_EVIDENCE_IOTLB,
            terminal_digest,
        )
        .unwrap();
        assert_eq!(
            harness.engine.check_reusable(
                resource(resource_value),
                cser_core::ResourceGeneration::new(1).unwrap()
            ),
            Ok(())
        );
    }
    assert_eq!(dma_retained_units(&harness, 10), 0);
    assert_eq!(
        harness
            .engine
            .component(effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .retirement,
        RetirementState::Retired
    );
}

/// Unknown evidence cannot become a retirement command, so the verified
/// ingress fails before it can change any custody state. This is deliberately
/// one global fail-closed rule rather than a per-class disposition hook.
#[test]
fn unsupported_retirement_evidence_is_failure_atomic_and_retains_the_resource() {
    let mut harness = Harness::standard();
    let (effect, _origin, subject) = committed_dma(&mut harness, 61, 61);
    let unsupported = EvidenceKindId::new(999).unwrap();
    let before = (
        harness.engine.revision(),
        harness.engine.head(),
        harness.engine.projection_digest(),
        harness
            .engine
            .component_claims(effect, AGENT_COMPONENT_DMA)
            .unwrap(),
        harness
            .engine
            .charge(charge(61), CREDIT_IOVA)
            .retained_units,
        harness.engine.check_reusable(
            resource(IOVA_RESOURCE),
            cser_core::ResourceGeneration::new(1).unwrap(),
        ),
    );
    let binding_challenge = harness
        .engine
        .component_evidence_challenge(
            effect,
            AGENT_COMPONENT_DMA,
            claim(IOVA_CLAIM),
            DEVICE_EVIDENCE_RESET,
        )
        .unwrap();
    let verifier = ExactTestVerifier::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA);
    let receipt = TestReceipt {
        effect,
        claim: claim(IOVA_CLAIM),
        kind: unsupported,
        resource: resource(IOVA_RESOURCE),
        resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
        subject,
        subject_binding: binding_challenge.subject_binding(),
        observation: subject,
        observation_binding: binding_challenge.current_binding(),
        digest: digest(61),
    };

    assert_eq!(
        harness.engine.verify_component_retirement_evidence(
            effect,
            AGENT_COMPONENT_DMA,
            claim(IOVA_CLAIM),
            unsupported,
            &verifier,
            &receipt,
        ),
        Err(CoreError::UnexpectedEvidence)
    );

    assert_eq!(
        (
            harness.engine.revision(),
            harness.engine.head(),
            harness.engine.projection_digest(),
            harness
                .engine
                .component_claims(effect, AGENT_COMPONENT_DMA)
                .unwrap(),
            harness
                .engine
                .charge(charge(61), CREDIT_IOVA)
                .retained_units,
            harness.engine.check_reusable(
                resource(IOVA_RESOURCE),
                cser_core::ResourceGeneration::new(1).unwrap(),
            ),
        ),
        before
    );
}

#[test]
fn device_generation_rejects_late_receipts_without_dropping_claims() {
    let mut harness = Harness::standard();
    let (effect, _, subject) = committed_dma(&mut harness, 20, 20);
    let before_pressure = harness.engine.pressure();

    let stale_reset = verified_evidence_command_at(
        &harness,
        effect,
        QUEUE_CLAIM,
        subject,
        DEVICE_EVIDENCE_RESET,
        subject,
        21,
    )
    .unwrap();
    submit(
        &mut harness,
        effect,
        subject,
        PAGE_CLAIM,
        DEVICE_EVIDENCE_RESET,
        20,
    )
    .unwrap();
    assert_eq!(
        harness.engine.pressure().retained_claims,
        before_pressure.retained_claims
    );
    assert_eq!(dma_retained_units(&harness, 20), 7);

    let before = harness.engine.projection_digest();
    assert_eq!(
        harness.tx(stale_reset),
        Err(CoreError::InvalidDeviceGenerationAdvance)
    );
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(
        harness.engine.check_reusable(
            resource(QUEUE_RESOURCE),
            cser_core::ResourceGeneration::new(1).unwrap()
        ),
        Err(CoreError::ResourceRetained)
    );

    submit(
        &mut harness,
        effect,
        subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_RESET,
        23,
    )
    .unwrap();
    submit(
        &mut harness,
        effect,
        subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_IRQ_DRAINED,
        24,
    )
    .unwrap();
    let (reuse_effect, reuse_actor) = registered_dma(&mut harness, 21);
    let permit = match harness.output(Command::ReserveComponentReuse {
        effect: reuse_effect,
        component: AGENT_COMPONENT_DMA,
        actor: reuse_actor,
        claim: claim(2101),
        kind: DEVICE_CLAIM_QUEUE_SLOT,
        scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
        resource: resource(QUEUE_RESOURCE),
        expected_generation: cser_core::ResourceGeneration::new(1).unwrap(),
        units: 1,
        reuse_contract: digest(201),
    }) {
        cser_core::TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected reuse permit, got {other:?}"),
    };
    assert_eq!(permit.freshness().device().get(), 2);
    assert_eq!(permit.generation().get(), 2);
    assert_eq!(
        harness
            .engine
            .component(reuse_effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .retained_claims,
        1
    );
    harness.tx(permit.activate()).unwrap();
}

#[test]
fn pending_reuse_is_reclaimed_only_after_each_explicit_crash_adoption() {
    let mut harness = Harness::standard();
    let (old_effect, _, subject) = committed_dma(&mut harness, 22, 22);
    submit(
        &mut harness,
        old_effect,
        subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_RESET,
        51,
    )
    .unwrap();
    submit(
        &mut harness,
        old_effect,
        subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_IRQ_DRAINED,
        52,
    )
    .unwrap();

    let (reuse_effect, first) = registered_dma(&mut harness, 23);
    let first_permit = match harness.output(Command::ReserveComponentReuse {
        effect: reuse_effect,
        component: AGENT_COMPONENT_DMA,
        actor: first,
        claim: claim(2301),
        kind: DEVICE_CLAIM_QUEUE_SLOT,
        scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
        resource: resource(QUEUE_RESOURCE),
        expected_generation: cser_core::ResourceGeneration::new(1).unwrap(),
        units: 1,
        reuse_contract: digest(202),
    }) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected first reuse permit, got {other:?}"),
    };
    let first_activation = first_permit.activate();

    let second = executor(23, 2);
    fence_and_rebind(&mut harness, reuse_effect, first, second, 2301);
    assert_eq!(harness.tx(first_activation), Err(CoreError::StaleExecutor));
    harness
        .tx(Command::AdoptEffect {
            effect: reuse_effect,
            successor: second,
        })
        .unwrap();
    let reclaim = harness
        .engine
        .reclaim_component_resource_reuse(
            reuse_effect,
            AGENT_COMPONENT_DMA,
            second,
            resource(QUEUE_RESOURCE),
            cser_core::ResourceGeneration::new(2).unwrap(),
        )
        .unwrap();
    let second_permit = match harness.output(reclaim) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected reclaimed reuse permit, got {other:?}"),
    };
    let second_activation = second_permit.activate();

    let third = executor(23, 3);
    fence_and_rebind(&mut harness, reuse_effect, second, third, 2302);
    assert_eq!(harness.tx(second_activation), Err(CoreError::StaleExecutor));
    harness
        .tx(Command::AdoptEffect {
            effect: reuse_effect,
            successor: third,
        })
        .unwrap();
    let reclaim = harness
        .engine
        .reclaim_component_resource_reuse(
            reuse_effect,
            AGENT_COMPONENT_DMA,
            third,
            resource(QUEUE_RESOURCE),
            cser_core::ResourceGeneration::new(2).unwrap(),
        )
        .unwrap();
    let third_permit = match harness.output(reclaim) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected second reclaimed reuse permit, got {other:?}"),
    };
    assert_eq!(third_permit.effect(), reuse_effect);
    assert_eq!(third_permit.generation().get(), 2);
    harness.tx(third_permit.activate()).unwrap();
    assert_eq!(
        harness
            .engine
            .component(reuse_effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .retained_claims,
        1
    );

    let report = Engine::recover(
        standard_catalog_set(),
        CoreLimits::bounded_default(),
        anchor(
            &harness.engine,
            freshness(1, 1, 1, 1),
            freshness(2, 1, 2, 2),
        ),
        &harness.journal,
    )
    .unwrap();
    assert_eq!(report.acknowledged_revision(), harness.engine.revision());
    assert_eq!(report.acknowledged_head(), harness.engine.head());
}

#[test]
fn late_old_generation_receipt_retires_only_its_exact_tombstone() {
    let mut harness = Harness::standard();
    let (old_effect, _, old_subject) = committed_dma(&mut harness, 25, 25);
    submit(
        &mut harness,
        old_effect,
        old_subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_RESET,
        25,
    )
    .unwrap();
    const NEW_RESOURCE_OFFSET: u64 = 1_000;
    let (new_effect, _, new_subject) =
        committed_dma_with_resource_offset(&mut harness, 26, 26, NEW_RESOURCE_OFFSET);
    assert_eq!(old_subject.device().get(), 1);
    assert_eq!(new_subject.device().get(), 2);

    submit(
        &mut harness,
        old_effect,
        old_subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_IRQ_DRAINED,
        26,
    )
    .unwrap();
    assert_eq!(
        harness.engine.check_reusable(
            resource(QUEUE_RESOURCE),
            cser_core::ResourceGeneration::new(1).unwrap()
        ),
        Ok(())
    );
    assert_eq!(
        harness.engine.check_reusable(
            resource(QUEUE_RESOURCE + NEW_RESOURCE_OFFSET),
            cser_core::ResourceGeneration::new(1).unwrap()
        ),
        Err(CoreError::ResourceRetained)
    );

    let before = harness.engine.projection_digest();
    let challenge = harness
        .engine
        .component_evidence_challenge(
            new_effect,
            AGENT_COMPONENT_DMA,
            claim(QUEUE_CLAIM),
            DEVICE_EVIDENCE_RESET,
        )
        .unwrap();
    let wrong_subject = TestReceipt {
        effect: new_effect,
        claim: claim(QUEUE_CLAIM),
        kind: DEVICE_EVIDENCE_RESET,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: old_subject,
        subject_binding: challenge.subject_binding(),
        observation: challenge
            .current_observation()
            .with_device(DeviceGeneration::new(3).unwrap()),
        observation_binding: challenge.current_binding(),
        digest: digest(29),
    };
    let verifier =
        ExactTestVerifier::new(cser_core::DEVICE_VERIFIER, cser_core::DEVICE_RECEIPT_SCHEMA);
    assert_eq!(
        harness.engine.verify_component_retirement_evidence(
            new_effect,
            AGENT_COMPONENT_DMA,
            claim(QUEUE_CLAIM),
            DEVICE_EVIDENCE_RESET,
            &verifier,
            &wrong_subject,
        ),
        Err(CoreError::VerificationFailed)
    );
    assert_eq!(harness.engine.projection_digest(), before);
    assert_eq!(dma_retained_units(&harness, 26), 7);

    submit(
        &mut harness,
        new_effect,
        new_subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_RESET,
        30,
    )
    .unwrap();
    submit(
        &mut harness,
        new_effect,
        new_subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_IRQ_DRAINED,
        31,
    )
    .unwrap();
    assert_eq!(
        harness.engine.check_reusable(
            resource(QUEUE_RESOURCE + NEW_RESOURCE_OFFSET),
            cser_core::ResourceGeneration::new(1).unwrap()
        ),
        Ok(())
    );
}

#[test]
fn journal_replay_preserves_exact_subject_and_ordered_retirement_high_water() {
    let mut before_crash = Harness::standard();
    let (effect, _, subject) = committed_dma(&mut before_crash, 27, 27);
    submit(
        &mut before_crash,
        effect,
        subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_RESET,
        33,
    )
    .unwrap();

    let report = Engine::recover(
        standard_catalog_set(),
        CoreLimits::bounded_default(),
        anchor(
            &before_crash.engine,
            freshness(1, 1, 1, 1),
            freshness(2, 1, 2, 2),
        ),
        &before_crash.journal,
    )
    .unwrap();
    let mut recovered = Harness {
        engine: report.into_engine(),
        journal: before_crash.journal,
    };
    recovered
        .tx(Command::CheckpointRecovery {
            boot: cser_core::BootGeneration::new(2).unwrap(),
            journal: cser_core::JournalGeneration::new(2).unwrap(),
            device: DeviceGeneration::new(2).unwrap(),
        })
        .unwrap();

    submit(
        &mut recovered,
        effect,
        subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_IRQ_DRAINED,
        34,
    )
    .unwrap();
    assert_eq!(
        recovered
            .engine
            .component(effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .retained_claims,
        2
    );
    assert_eq!(dma_retained_units(&recovered, 27), 6);
}

#[test]
fn one_account_backpressures_without_blocking_an_unrelated_operation() {
    let limits = CoreLimits::new(8, 8, 16, 16, 8, 3, 8).unwrap();
    let mut harness = Harness::with_catalog(standard_catalog(), limits);
    let first = effect(30, 1);
    let first_origin = executor(30, 1);
    admit_dma(&mut harness, first, first_origin, 30);
    add_dma_claim(
        &mut harness,
        first,
        first_origin,
        DmaClaimRequest {
            claim_value: 301,
            kind: DEVICE_CLAIM_IOVA,
            scope_value: 1,
            resource_value: 301,
            units: 3,
        },
    )
    .unwrap();
    let before = harness.engine.projection_digest();
    assert_eq!(
        add_dma_claim(
            &mut harness,
            first,
            first_origin,
            DmaClaimRequest {
                claim_value: 302,
                kind: DEVICE_CLAIM_IOVA,
                scope_value: 1,
                resource_value: 302,
                units: 1,
            },
        ),
        Err(CoreError::Backpressure)
    );
    assert_eq!(harness.engine.projection_digest(), before);
    add_dma_claim(
        &mut harness,
        first,
        first_origin,
        DmaClaimRequest {
            claim_value: 303,
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope_value: 1,
            resource_value: 303,
            units: 1,
        },
    )
    .unwrap();

    let unrelated = effect(31, 1);
    let unrelated_origin = executor(31, 1);
    admit_dma(&mut harness, unrelated, unrelated_origin, 31);
    add_dma_claim(
        &mut harness,
        unrelated,
        unrelated_origin,
        DmaClaimRequest {
            claim_value: 311,
            kind: DEVICE_CLAIM_PINNED_PAGE,
            scope_value: 2,
            resource_value: 311,
            units: 3,
        },
    )
    .unwrap();
    assert_eq!(dma_retained_units(&harness, 30), 4);
    assert_eq!(dma_retained_units(&harness, 31), 3);
    assert_eq!(harness.engine.pressure().retained_claims, 3);
}

#[test]
fn reboot_recovers_device_tombstones_under_quarantine_until_fresh_evidence() {
    let mut before_crash = Harness::standard();
    let (effect, origin, old_freshness) = committed_dma(&mut before_crash, 40, 40);
    before_crash
        .tx(Command::FenceExecutor {
            operation: effect.operation(),
            crashed: origin,
        })
        .unwrap();
    let acknowledged_revision = before_crash.engine.revision();
    let acknowledged_head = before_crash.engine.head();

    let report = Engine::recover(
        standard_catalog_set(),
        CoreLimits::bounded_default(),
        anchor(
            &before_crash.engine,
            freshness(1, 1, 1, 1),
            freshness(2, 1, 2, 2),
        ),
        &before_crash.journal,
    )
    .unwrap();
    assert_eq!(report.acknowledged_revision(), acknowledged_revision);
    assert_eq!(report.acknowledged_head(), acknowledged_head);
    assert_eq!(report.torn_tail(), None);
    let mut recovered = Harness {
        engine: report.into_engine(),
        journal: before_crash.journal,
    };

    assert_eq!(recovered.engine.pressure().retained_claims, 3);
    assert!(recovered.engine.pressure().quarantined);
    let tombstone = recovered.engine.composite_effect(effect).unwrap();
    assert_eq!(tombstone.causal_owner, origin);
    assert_eq!(tombstone.authority, AuthorityState::Fenced);
    assert_eq!(
        recovered
            .engine
            .component(effect, AGENT_COMPONENT_DMA)
            .unwrap()
            .retirement,
        RetirementState::RetirementPending
    );
    assert_eq!(dma_retained_units(&recovered, 40), 7);
    assert_eq!(
        recovered.engine.check_reusable(
            resource(IOVA_RESOURCE),
            cser_core::ResourceGeneration::new(1).unwrap()
        ),
        Err(CoreError::RecoveryPending)
    );
    recovered
        .tx(Command::CheckpointRecovery {
            boot: cser_core::BootGeneration::new(2).unwrap(),
            journal: cser_core::JournalGeneration::new(2).unwrap(),
            device: DeviceGeneration::new(2).unwrap(),
        })
        .unwrap();
    assert_eq!(
        recovered
            .engine
            .device_generation(cser_core::DeviceScopeId::new(1).unwrap()),
        DeviceGeneration::new(2).ok()
    );
    assert_eq!(
        recovered.engine.check_reusable(
            resource(IOVA_RESOURCE),
            cser_core::ResourceGeneration::new(1).unwrap()
        ),
        Err(CoreError::ResourceRetained)
    );

    let before = recovered.engine.projection_digest();
    let challenge = recovered
        .engine
        .component_evidence_challenge(
            effect,
            AGENT_COMPONENT_DMA,
            claim(IOVA_CLAIM),
            DEVICE_EVIDENCE_RESET,
        )
        .unwrap();
    assert_eq!(challenge.subject().device(), old_freshness.device());
    assert_eq!(
        challenge.current_observation().device(),
        DeviceGeneration::new(2).unwrap()
    );
    let wrong_subject = TestReceipt {
        effect,
        claim: claim(IOVA_CLAIM),
        kind: DEVICE_EVIDENCE_RESET,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: recovered.engine.freshness(),
        subject_binding: challenge.subject_binding(),
        observation: challenge
            .current_observation()
            .with_device(DeviceGeneration::new(2).unwrap()),
        observation_binding: challenge.current_binding(),
        digest: digest(40),
    };
    let verifier =
        ExactTestVerifier::new(cser_core::DEVICE_VERIFIER, cser_core::DEVICE_RECEIPT_SCHEMA);
    assert_eq!(
        recovered.engine.verify_component_retirement_evidence(
            effect,
            AGENT_COMPONENT_DMA,
            claim(IOVA_CLAIM),
            DEVICE_EVIDENCE_RESET,
            &verifier,
            &wrong_subject,
        ),
        Err(CoreError::VerificationFailed)
    );
    assert_eq!(recovered.engine.projection_digest(), before);

    let stale_reset = verified_evidence_command_at(
        &recovered,
        effect,
        IOVA_CLAIM,
        old_freshness,
        DEVICE_EVIDENCE_RESET,
        old_freshness,
        41,
    )
    .unwrap();
    let before = recovered.engine.projection_digest();
    assert_eq!(
        recovered.tx(stale_reset),
        Err(CoreError::InvalidDeviceGenerationAdvance)
    );
    assert_eq!(recovered.engine.projection_digest(), before);

    for (claim_value, kind, digest_value) in [
        (QUEUE_CLAIM, DEVICE_EVIDENCE_RESET, 42),
        (QUEUE_CLAIM, DEVICE_EVIDENCE_IRQ_DRAINED, 43),
        (PAGE_CLAIM, DEVICE_EVIDENCE_RESET, 44),
        (PAGE_CLAIM, DEVICE_EVIDENCE_IOTLB, 45),
        (IOVA_CLAIM, DEVICE_EVIDENCE_RESET, 46),
        (IOVA_CLAIM, DEVICE_EVIDENCE_IOTLB, 47),
    ] {
        submit(
            &mut recovered,
            effect,
            old_freshness,
            claim_value,
            kind,
            digest_value,
        )
        .unwrap();
    }
    assert_eq!(recovered.engine.pressure().retained_claims, 0);
    assert_eq!(dma_retained_units(&recovered, 40), 0);
    assert_eq!(
        recovered.engine.check_reusable(
            resource(PAGE_RESOURCE),
            cser_core::ResourceGeneration::new(1).unwrap()
        ),
        Ok(())
    );

    assert!(!recovered.engine.pressure().quarantined);
    let (reuse_effect, reuse_actor) = registered_dma(&mut recovered, 41);
    for (offset, resource_value, kind) in [
        (1, QUEUE_RESOURCE, DEVICE_CLAIM_QUEUE_SLOT),
        (2, PAGE_RESOURCE, DEVICE_CLAIM_PINNED_PAGE),
        (3, IOVA_RESOURCE, DEVICE_CLAIM_IOVA),
    ] {
        let permit = match recovered.output(Command::ReserveComponentReuse {
            effect: reuse_effect,
            component: AGENT_COMPONENT_DMA,
            actor: reuse_actor,
            claim: claim(4100 + offset),
            kind,
            scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
            resource: resource(resource_value),
            expected_generation: cser_core::ResourceGeneration::new(1).unwrap(),
            units: 1,
            reuse_contract: digest(203),
        }) {
            cser_core::TransitionOutput::ReusePermit(permit) => permit,
            other => panic!("expected reuse permit, got {other:?}"),
        };
        assert_eq!(permit.resource(), resource(resource_value));
        assert_eq!(permit.generation().get(), 2);
        assert_eq!(permit.freshness(), freshness(2, 1, 2, 2));
        recovered.tx(permit.activate()).unwrap();
    }
}

#[test]
fn recovery_checkpoint_rejects_a_target_below_any_known_device_scope() {
    let mut before_crash = Harness::standard();
    let (effect, _origin, subject) = committed_dma(&mut before_crash, 42, 42);
    submit(
        &mut before_crash,
        effect,
        subject,
        QUEUE_CLAIM,
        DEVICE_EVIDENCE_RESET,
        50,
    )
    .unwrap();
    let scope = cser_core::DeviceScopeId::new(1).unwrap();
    assert_eq!(
        before_crash.engine.device_generation(scope),
        DeviceGeneration::new(2).ok()
    );

    let report = Engine::recover(
        standard_catalog_set(),
        CoreLimits::bounded_default(),
        anchor(
            &before_crash.engine,
            freshness(1, 1, 1, 1),
            freshness(2, 1, 1, 2),
        ),
        &before_crash.journal,
    )
    .unwrap();
    let mut recovered = Harness {
        engine: report.into_engine(),
        journal: before_crash.journal,
    };
    let before = (
        recovered.engine.revision(),
        recovered.engine.head(),
        recovered.engine.projection_digest(),
        recovered.engine.freshness(),
        recovered.engine.device_generation(scope),
        recovered.journal.len(),
    );

    assert_eq!(
        recovered.tx(Command::CheckpointRecovery {
            boot: cser_core::BootGeneration::new(2).unwrap(),
            journal: cser_core::JournalGeneration::new(2).unwrap(),
            device: DeviceGeneration::new(1).unwrap(),
        }),
        Err(CoreError::FreshnessRollback)
    );
    assert_eq!(
        (
            recovered.engine.revision(),
            recovered.engine.head(),
            recovered.engine.projection_digest(),
            recovered.engine.freshness(),
            recovered.engine.device_generation(scope),
            recovered.journal.len(),
        ),
        before
    );
    assert!(recovered.engine.pressure().quarantined);
}

#[test]
fn recovery_checkpoint_refreshes_a_retired_scope_before_composite_reuse() {
    let mut before_crash = Harness::standard();
    let (old_effect, _origin, subject) = committed_dma(&mut before_crash, 43, 43);
    for (claim_value, kind, digest_value) in [
        (QUEUE_CLAIM, DEVICE_EVIDENCE_RESET, 60),
        (QUEUE_CLAIM, DEVICE_EVIDENCE_IRQ_DRAINED, 61),
        (PAGE_CLAIM, DEVICE_EVIDENCE_RESET, 62),
        (PAGE_CLAIM, DEVICE_EVIDENCE_IOTLB, 63),
        (IOVA_CLAIM, DEVICE_EVIDENCE_RESET, 64),
        (IOVA_CLAIM, DEVICE_EVIDENCE_IOTLB, 65),
    ] {
        submit(
            &mut before_crash,
            old_effect,
            subject,
            claim_value,
            kind,
            digest_value,
        )
        .unwrap();
    }
    let scope = cser_core::DeviceScopeId::new(1).unwrap();
    assert_eq!(before_crash.engine.pressure().retained_claims, 0);
    assert_eq!(
        before_crash.engine.device_generation(scope),
        DeviceGeneration::new(2).ok()
    );

    let report = Engine::recover(
        standard_catalog_set(),
        CoreLimits::bounded_default(),
        anchor(
            &before_crash.engine,
            freshness(1, 1, 1, 1),
            freshness(2, 1, 3, 2),
        ),
        &before_crash.journal,
    )
    .unwrap();
    let mut recovered = Harness {
        engine: report.into_engine(),
        journal: before_crash.journal,
    };
    assert_eq!(
        recovered.engine.device_generation(scope),
        DeviceGeneration::new(2).ok()
    );
    recovered
        .tx(Command::CheckpointRecovery {
            boot: cser_core::BootGeneration::new(2).unwrap(),
            journal: cser_core::JournalGeneration::new(2).unwrap(),
            device: DeviceGeneration::new(3).unwrap(),
        })
        .unwrap();
    assert_eq!(
        recovered.engine.device_generation(scope),
        DeviceGeneration::new(3).ok()
    );

    let reuse_effect = effect(44, 1);
    let reuse_actor = executor(44, 1);
    admit_dma(&mut recovered, reuse_effect, reuse_actor, 44);
    let permit = match recovered.output(Command::ReserveComponentReuse {
        effect: reuse_effect,
        component: AGENT_COMPONENT_DMA,
        actor: reuse_actor,
        claim: claim(4401),
        kind: DEVICE_CLAIM_QUEUE_SLOT,
        scope: cser_core::ClaimScope::Device(scope),
        resource: resource(QUEUE_RESOURCE),
        expected_generation: cser_core::ResourceGeneration::new(1).unwrap(),
        units: 1,
        reuse_contract: digest(204),
    }) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected component reuse permit, got {other:?}"),
    };
    assert_eq!(permit.component(), AGENT_COMPONENT_DMA);
    assert_eq!(permit.generation().get(), 2);
    assert_eq!(permit.freshness(), freshness(2, 1, 3, 2));
    recovered.tx(permit.activate()).unwrap();
    recovered
        .tx(Command::PrepareCompositeEffect {
            effect: reuse_effect,
            actor: reuse_actor,
        })
        .unwrap();
    let intent = match recovered.output(Command::RecordComponentCommitIntent {
        effect: reuse_effect,
        component: AGENT_COMPONENT_DMA,
        actor: reuse_actor,
        operation: digest(66),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected component commit intent, got {other:?}"),
    };
    assert_eq!(
        recovered
            .engine
            .commit_outcome_challenge(&intent)
            .unwrap()
            .current_observation()
            .device(),
        DeviceGeneration::new(3).unwrap()
    );
}

/// Backpressure must be scoped to the charge account, not to the credit class
/// globally.
///
/// The paper's falsification criterion is that a design "safe only by globally
/// freezing all resources is not an adequate custody abstraction." The
/// neighbouring test exercises a second account at a *different* credit class,
/// so it would still pass if the ceiling were keyed on class alone. This drives
/// one account to its ceiling and then requires a second account to admit a
/// claim of the very same class.
#[test]
fn an_exhausted_account_does_not_freeze_the_same_credit_class_elsewhere() {
    let limits = CoreLimits::new(8, 8, 16, 16, 8, 3, 8).unwrap();
    let mut harness = Harness::with_catalog(standard_catalog(), limits);

    let saturated = effect(40, 1);
    let saturated_origin = executor(40, 1);
    admit_dma(&mut harness, saturated, saturated_origin, 40);
    add_dma_claim(
        &mut harness,
        saturated,
        saturated_origin,
        DmaClaimRequest {
            claim_value: 401,
            kind: DEVICE_CLAIM_IOVA,
            scope_value: 1,
            resource_value: 401,
            units: 3,
        },
    )
    .unwrap();
    assert_eq!(
        harness
            .engine
            .charge(charge(40), CREDIT_IOVA)
            .retained_units,
        3
    );

    // Same class, same units, different account: admission must not consult a
    // neighbour's retention.
    let unrelated = effect(41, 1);
    let unrelated_origin = executor(41, 1);
    admit_dma(&mut harness, unrelated, unrelated_origin, 41);
    add_dma_claim(
        &mut harness,
        unrelated,
        unrelated_origin,
        DmaClaimRequest {
            claim_value: 411,
            kind: DEVICE_CLAIM_IOVA,
            scope_value: 2,
            resource_value: 411,
            units: 3,
        },
    )
    .expect("an unrelated account must not inherit a neighbour's ceiling");

    assert_eq!(
        harness
            .engine
            .charge(charge(41), CREDIT_IOVA)
            .retained_units,
        3
    );
    // The saturated account is still saturated: relief came from scoping, not
    // from raising the ceiling.
    assert_eq!(
        add_dma_claim(
            &mut harness,
            saturated,
            saturated_origin,
            DmaClaimRequest {
                claim_value: 402,
                kind: DEVICE_CLAIM_IOVA,
                scope_value: 1,
                resource_value: 402,
                units: 1,
            },
        ),
        Err(CoreError::Backpressure)
    );
    assert_eq!(
        harness
            .engine
            .charge(charge(40), CREDIT_IOVA)
            .retained_units,
        3,
        "a refused admission must leave the live claim charged",
    );

    // This is the paired headroom control for the negative assertion above.
    // It uses the same account/class/claim shape under a higher limit, so the
    // refusal is pinned to the configured ceiling rather than another gate.
    let mut headroom = Harness::with_catalog(
        standard_catalog(),
        CoreLimits::new(8, 8, 16, 16, 8, 4, 8).unwrap(),
    );
    let admitted = effect(42, 1);
    let admitted_origin = executor(42, 1);
    admit_dma(&mut headroom, admitted, admitted_origin, 42);
    for (claim_value, resource_value, units) in [(421, 421, 3), (422, 422, 1)] {
        add_dma_claim(
            &mut headroom,
            admitted,
            admitted_origin,
            DmaClaimRequest {
                claim_value,
                kind: DEVICE_CLAIM_IOVA,
                scope_value: 3,
                resource_value,
                units,
            },
        )
        .expect("raising only the unit ceiling must admit the same IOVA shape");
    }
    assert_eq!(
        headroom
            .engine
            .charge(charge(42), CREDIT_IOVA)
            .retained_units,
        4
    );
}

/// Retention pressure must be transient, released by evidence rather than by
/// time.
///
/// This is what licenses measuring bounded retention occupancy at all: the
/// claim-revision integral is finite because discharge returns its units. The two
/// halves are pinned separately elsewhere -- that a ceiling rejects, and that
/// retirement zeroes a charge -- but never composed, so nothing would catch a
/// regression where retirement decremented the counter while an admission gate
/// stayed latched.
#[test]
fn evidence_backed_retirement_readmits_what_backpressure_refused() {
    // `max_units_per_account` is a single ceiling applied per (account, class),
    // so 4 admits committed_dma's page claim (4 units) exactly while leaving
    // the IOVA class holding 2 of its 4.
    let limits = CoreLimits::new(8, 8, 16, 16, 8, 4, 8).unwrap();
    let mut harness = Harness::with_catalog(standard_catalog(), limits);
    let (retained, origin, subject) = committed_dma(&mut harness, 50, 50);
    assert_eq!(
        harness
            .engine
            .charge(charge(50), CREDIT_IOVA)
            .retained_units,
        2
    );

    fence_and_rebind(&mut harness, retained, origin, executor(50, 2), 50);

    // Saturated: this account's IOVA credit class retains two units, so the
    // three-unit claim below exceeds its four-unit ceiling. Its resource
    // coordinate is new; this is a quota gate, not a resource-conflict gate.
    let successor = effect(50, 2);
    admit_dma_at(&mut harness, successor, executor(50, 2), 50);
    let refused = Command::AddComponentClaim {
        effect: successor,
        component: AGENT_COMPONENT_DMA,
        actor: executor(50, 2),
        claim: claim(503),
        kind: DEVICE_CLAIM_IOVA,
        scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
        resource: resource(503),
        resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
        units: 3,
    };
    let before = harness.engine.projection_digest();
    assert_eq!(harness.tx(refused), Err(CoreError::Backpressure));
    assert_eq!(harness.engine.projection_digest(), before);

    // Discharge the retained IOVA claim with its exact evidence conjunction.
    submit(
        &mut harness,
        retained,
        subject,
        IOVA_CLAIM,
        DEVICE_EVIDENCE_RESET,
        51,
    )
    .unwrap();
    submit(
        &mut harness,
        retained,
        subject,
        IOVA_CLAIM,
        DEVICE_EVIDENCE_IOTLB,
        52,
    )
    .unwrap();
    assert_eq!(
        harness
            .engine
            .charge(charge(50), CREDIT_IOVA)
            .retained_units,
        0,
        "discharging the claim must return its conserved units",
    );

    // The identical command now admits. Nothing about the ceiling changed.
    harness
        .tx(Command::AddComponentClaim {
            effect: successor,
            component: AGENT_COMPONENT_DMA,
            actor: executor(50, 2),
            claim: claim(503),
            kind: DEVICE_CLAIM_IOVA,
            scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
            resource: resource(503),
            resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
            units: 3,
        })
        .expect("evidence-backed release must readmit the refused claim");
    assert_eq!(
        harness
            .engine
            .charge(charge(50), CREDIT_IOVA)
            .retained_units,
        3
    );

    // Paired headroom control: preserve the committed retained claim and the
    // successor's request, changing only the per-account unit ceiling.
    let mut headroom = Harness::with_catalog(
        standard_catalog(),
        CoreLimits::new(8, 8, 16, 16, 8, 5, 8).unwrap(),
    );
    let (retained, origin, _) = committed_dma(&mut headroom, 51, 51);
    fence_and_rebind(&mut headroom, retained, origin, executor(51, 2), 51);
    let successor = effect(51, 2);
    admit_dma_at(&mut headroom, successor, executor(51, 2), 51);
    add_dma_claim_at(
        &mut headroom,
        successor,
        executor(51, 2),
        DmaClaimRequest {
            claim_value: 513,
            kind: DEVICE_CLAIM_IOVA,
            scope_value: 1,
            resource_value: 513,
            units: 3,
        },
    )
    .expect("raising only the unit ceiling must admit the previously refused request");
    assert_eq!(
        headroom
            .engine
            .charge(charge(51), CREDIT_IOVA)
            .retained_units,
        5
    );
}
