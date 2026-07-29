#[allow(dead_code)]
mod support;

use cser_core::{
    AuthorityState, CREDIT_IOVA, CREDIT_PINNED_PAGE, CREDIT_QUEUE_SLOT,
    Command as AuthorizedCommand, CommandRequest as Command, CommitState, CoreError, CoreLimits,
    DEVICE_CLAIM_IOVA, DEVICE_CLAIM_PINNED_PAGE, DEVICE_CLAIM_QUEUE_SLOT, DEVICE_DOMAIN,
    DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_IRQ_DRAINED, DEVICE_EVIDENCE_RESET,
    DEVICE_OBLIGATION_DMA, DeviceGeneration, Engine, ExternalOutcome, Freshness, RecoveryAnchor,
    RetirementState, TransitionOutput, standard_catalog,
};
use support::{
    ExactTestVerifier, Harness, TestReceipt, charge, claim, digest, effect, fence_and_rebind,
    freshness, principal, resource, verified_commit_outcome,
    verified_evidence_command as verified_evidence_with_observation,
};

const QUEUE_CLAIM: u64 = 101;
const PAGE_CLAIM: u64 = 102;
const IOVA_CLAIM: u64 = 103;
const QUEUE_RESOURCE: u64 = 201;
const PAGE_RESOURCE: u64 = 202;
const IOVA_RESOURCE: u64 = 203;

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

fn registered_dma(
    harness: &mut Harness,
    root_value: u64,
) -> (cser_core::EffectId, cser_core::PrincipalIncarnation) {
    let effect = effect(root_value, 1);
    let origin = principal(root_value, 1);
    harness
        .tx(Command::CreateEstate {
            effect,
            origin,
            binding_generation: 1,
            domain: DEVICE_DOMAIN,
            obligation: DEVICE_OBLIGATION_DMA,
            charge_account: charge(root_value),
        })
        .unwrap();
    (effect, origin)
}

fn committed_dma(
    harness: &mut Harness,
    root_value: u64,
    account_value: u64,
) -> (
    cser_core::EffectId,
    cser_core::PrincipalIncarnation,
    Freshness,
) {
    let effect = effect(root_value, 1);
    let origin = principal(root_value, 1);
    harness
        .tx(Command::CreateEstate {
            effect,
            origin,
            binding_generation: 1,
            domain: DEVICE_DOMAIN,
            obligation: DEVICE_OBLIGATION_DMA,
            charge_account: charge(account_value),
        })
        .unwrap();
    for (claim_value, kind, resource_value, units) in [
        (QUEUE_CLAIM, DEVICE_CLAIM_QUEUE_SLOT, QUEUE_RESOURCE, 1),
        (PAGE_CLAIM, DEVICE_CLAIM_PINNED_PAGE, PAGE_RESOURCE, 4),
        (IOVA_CLAIM, DEVICE_CLAIM_IOVA, IOVA_RESOURCE, 2),
    ] {
        harness
            .tx(Command::AddClaim {
                effect,
                actor: origin,
                binding_generation: 1,
                claim: claim(claim_value),
                domain: DEVICE_DOMAIN,
                kind,
                scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
                resource: resource(resource_value),
                resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
                units,
            })
            .unwrap();
    }
    harness
        .tx(Command::PrepareEffect {
            effect,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    let intent = match harness.output(Command::RecordCommitIntent {
        effect,
        actor: origin,
        binding_generation: 1,
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
        .evidence_challenge(effect, claim(QUEUE_CLAIM), DEVICE_EVIDENCE_RESET)
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
    let challenge = harness
        .engine
        .evidence_challenge(effect, claim(claim_value), kind)?;
    let current = challenge.current_observation();
    let observation = if kind == DEVICE_EVIDENCE_RESET && current.device() == subject.device() {
        Freshness::new(
            current.boot(),
            current.registry(),
            current.binding(),
            DeviceGeneration::new(current.device().get() + 1).unwrap(),
            current.journal(),
        )
        .unwrap()
    } else {
        current
    };
    let receipt = TestReceipt {
        effect,
        claim: claim(claim_value),
        kind,
        subject,
        observation,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        digest: digest(digest_value),
    };
    let verifier =
        ExactTestVerifier::new(cser_core::DEVICE_VERIFIER, cser_core::DEVICE_RECEIPT_SCHEMA);
    harness
        .engine
        .verify_retirement_evidence(effect, claim(claim_value), kind, &verifier, &receipt)
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
    let mut harness = Harness::new();
    let (effect, origin, subject) = committed_dma(&mut harness, 10, 10);
    harness
        .tx(Command::FenceIncarnation {
            root: effect.root(),
            crashed: origin,
            binding_generation: 1,
        })
        .unwrap();

    let estate = harness.engine.estate(effect).unwrap();
    assert_eq!(estate.commit, CommitState::Committed);
    assert_eq!(estate.retirement, RetirementState::RetirementPending);
    assert_eq!(estate.retained_claims, 3);
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
        harness.engine.estate(effect).unwrap().retirement,
        RetirementState::Retired
    );
}

#[test]
fn device_generation_rejects_late_receipts_without_dropping_claims() {
    let mut harness = Harness::new();
    let (effect, _, subject) = committed_dma(&mut harness, 20, 20);
    let before_pressure = harness.engine.pressure();

    let stale_reset = verified_evidence_with_observation(
        &harness,
        effect,
        claim(QUEUE_CLAIM),
        DEVICE_EVIDENCE_RESET,
        cser_core::ReceiptBinding::new(
            cser_core::DEVICE_VERIFIER,
            cser_core::DEVICE_RECEIPT_SCHEMA,
        ),
        subject,
        digest(21),
    );
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
    let permit = match harness.output(Command::ReserveReuse {
        effect: reuse_effect,
        actor: reuse_actor,
        binding_generation: 1,
        claim: claim(2101),
        domain: DEVICE_DOMAIN,
        kind: DEVICE_CLAIM_QUEUE_SLOT,
        scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
        resource: resource(QUEUE_RESOURCE),
        expected_generation: cser_core::ResourceGeneration::new(1).unwrap(),
        units: 1,
    }) {
        cser_core::TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected reuse permit, got {other:?}"),
    };
    assert_eq!(permit.freshness().device().get(), 2);
    assert_eq!(permit.generation().get(), 2);
    assert_eq!(
        harness.engine.estate(reuse_effect).unwrap().retained_claims,
        1
    );
    harness.tx(permit.activate()).unwrap();
}

#[test]
fn pending_reuse_is_reclaimed_only_after_each_explicit_crash_adoption() {
    let mut harness = Harness::new();
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
    let first_permit = match harness.output(Command::ReserveReuse {
        effect: reuse_effect,
        actor: first,
        binding_generation: 1,
        claim: claim(2301),
        domain: DEVICE_DOMAIN,
        kind: DEVICE_CLAIM_QUEUE_SLOT,
        scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
        resource: resource(QUEUE_RESOURCE),
        expected_generation: cser_core::ResourceGeneration::new(1).unwrap(),
        units: 1,
    }) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected first reuse permit, got {other:?}"),
    };
    let first_activation = first_permit.activate();

    let second = principal(23, 2);
    fence_and_rebind(&mut harness, reuse_effect, first, second, 1, 2, 2301);
    assert_eq!(
        harness.tx(first_activation),
        Err(CoreError::StaleIncarnation)
    );
    harness
        .tx(Command::AdoptEffect {
            effect: reuse_effect,
            successor: second,
            binding_generation: 2,
        })
        .unwrap();
    let reclaim = harness
        .engine
        .reclaim_resource_reuse(
            reuse_effect,
            second,
            2,
            resource(QUEUE_RESOURCE),
            cser_core::ResourceGeneration::new(2).unwrap(),
        )
        .unwrap();
    let second_permit = match harness.output(reclaim) {
        TransitionOutput::ReusePermit(permit) => permit,
        other => panic!("expected reclaimed reuse permit, got {other:?}"),
    };
    let second_activation = second_permit.activate();

    let third = principal(23, 3);
    fence_and_rebind(&mut harness, reuse_effect, second, third, 2, 3, 2302);
    assert_eq!(
        harness.tx(second_activation),
        Err(CoreError::StaleIncarnation)
    );
    harness
        .tx(Command::AdoptEffect {
            effect: reuse_effect,
            successor: third,
            binding_generation: 3,
        })
        .unwrap();
    let reclaim = harness
        .engine
        .reclaim_resource_reuse(
            reuse_effect,
            third,
            3,
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
        harness.engine.estate(reuse_effect).unwrap().retained_claims,
        1
    );

    let report = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 2, 2),
            harness.engine.revision(),
            harness.engine.head(),
        )
        .unwrap(),
        &harness.journal,
    )
    .unwrap();
    assert_eq!(report.acknowledged_revision(), harness.engine.revision());
    assert_eq!(report.acknowledged_head(), harness.engine.head());
}

#[test]
fn late_old_generation_receipt_retires_only_its_exact_tombstone() {
    let mut harness = Harness::new();
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
    let (new_effect, _, new_subject) = committed_dma(&mut harness, 26, 26);
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
        Err(CoreError::ResourceRetained)
    );

    let before = harness.engine.projection_digest();
    let challenge = harness
        .engine
        .evidence_challenge(new_effect, claim(QUEUE_CLAIM), DEVICE_EVIDENCE_RESET)
        .unwrap();
    let wrong_subject = TestReceipt {
        effect: new_effect,
        claim: claim(QUEUE_CLAIM),
        kind: DEVICE_EVIDENCE_RESET,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: old_subject,
        observation: challenge
            .current_observation()
            .with_device(DeviceGeneration::new(3).unwrap()),
        digest: digest(29),
    };
    let verifier =
        ExactTestVerifier::new(cser_core::DEVICE_VERIFIER, cser_core::DEVICE_RECEIPT_SCHEMA);
    assert_eq!(
        harness.engine.verify_retirement_evidence(
            new_effect,
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
            resource(QUEUE_RESOURCE),
            cser_core::ResourceGeneration::new(1).unwrap()
        ),
        Ok(())
    );
}

#[test]
fn journal_replay_preserves_exact_subject_and_ordered_retirement_high_water() {
    let mut before_crash = Harness::new();
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

    let acknowledged_revision = before_crash.engine.revision();
    let acknowledged_head = before_crash.engine.head();
    let report = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 2, 2),
            acknowledged_revision,
            acknowledged_head,
        )
        .unwrap(),
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
    assert_eq!(recovered.engine.estate(effect).unwrap().retained_claims, 2);
    assert_eq!(dma_retained_units(&recovered, 27), 6);
}

#[test]
fn one_account_backpressures_without_blocking_an_unrelated_root() {
    let limits = CoreLimits::new(8, 8, 16, 16, 8, 3, 8).unwrap();
    let mut harness = Harness::with_limits(limits);
    let first = effect(30, 1);
    harness
        .tx(Command::CreateEstate {
            effect: first,
            origin: principal(30, 1),
            binding_generation: 1,
            domain: DEVICE_DOMAIN,
            obligation: DEVICE_OBLIGATION_DMA,
            charge_account: charge(30),
        })
        .unwrap();
    harness
        .tx(Command::AddClaim {
            effect: first,
            actor: principal(30, 1),
            binding_generation: 1,
            claim: claim(301),
            domain: DEVICE_DOMAIN,
            kind: DEVICE_CLAIM_IOVA,
            scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
            resource: resource(301),
            resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
            units: 3,
        })
        .unwrap();
    let before = harness.engine.projection_digest();
    assert_eq!(
        harness.tx(Command::AddClaim {
            effect: first,
            actor: principal(30, 1),
            binding_generation: 1,
            claim: claim(302),
            domain: DEVICE_DOMAIN,
            kind: DEVICE_CLAIM_IOVA,
            scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
            resource: resource(302),
            resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
            units: 1,
        }),
        Err(CoreError::Backpressure)
    );
    assert_eq!(harness.engine.projection_digest(), before);
    harness
        .tx(Command::AddClaim {
            effect: first,
            actor: principal(30, 1),
            binding_generation: 1,
            claim: claim(303),
            domain: DEVICE_DOMAIN,
            kind: DEVICE_CLAIM_QUEUE_SLOT,
            scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
            resource: resource(303),
            resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
            units: 1,
        })
        .unwrap();

    let unrelated = effect(31, 1);
    harness
        .tx(Command::CreateEstate {
            effect: unrelated,
            origin: principal(31, 1),
            binding_generation: 1,
            domain: DEVICE_DOMAIN,
            obligation: DEVICE_OBLIGATION_DMA,
            charge_account: charge(31),
        })
        .unwrap();
    harness
        .tx(Command::AddClaim {
            effect: unrelated,
            actor: principal(31, 1),
            binding_generation: 1,
            claim: claim(311),
            domain: DEVICE_DOMAIN,
            kind: DEVICE_CLAIM_PINNED_PAGE,
            scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(2).unwrap()),
            resource: resource(311),
            resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
            units: 3,
        })
        .unwrap();
    assert_eq!(dma_retained_units(&harness, 30), 4);
    assert_eq!(dma_retained_units(&harness, 31), 3);
    assert_eq!(harness.engine.pressure().retained_claims, 3);
}

#[test]
fn reboot_recovers_device_tombstones_under_quarantine_until_fresh_evidence() {
    let mut before_crash = Harness::new();
    let (effect, origin, old_freshness) = committed_dma(&mut before_crash, 40, 40);
    before_crash
        .tx(Command::FenceIncarnation {
            root: effect.root(),
            crashed: origin,
            binding_generation: 1,
        })
        .unwrap();
    let acknowledged_revision = before_crash.engine.revision();
    let acknowledged_head = before_crash.engine.head();

    let report = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 2, 2),
            acknowledged_revision,
            acknowledged_head,
        )
        .unwrap(),
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
    let tombstone = recovered.engine.estate(effect).unwrap();
    assert_eq!(tombstone.causal_owner, origin);
    assert_eq!(tombstone.authority, AuthorityState::Fenced);
    assert_eq!(tombstone.retirement, RetirementState::RetirementPending);
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
        recovered.engine.check_reusable(
            resource(IOVA_RESOURCE),
            cser_core::ResourceGeneration::new(1).unwrap()
        ),
        Err(CoreError::ResourceRetained)
    );

    let before = recovered.engine.projection_digest();
    let challenge = recovered
        .engine
        .evidence_challenge(effect, claim(IOVA_CLAIM), DEVICE_EVIDENCE_RESET)
        .unwrap();
    let wrong_subject = TestReceipt {
        effect,
        claim: claim(IOVA_CLAIM),
        kind: DEVICE_EVIDENCE_RESET,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: recovered.engine.freshness(),
        observation: challenge
            .current_observation()
            .with_device(DeviceGeneration::new(2).unwrap()),
        digest: digest(40),
    };
    let verifier =
        ExactTestVerifier::new(cser_core::DEVICE_VERIFIER, cser_core::DEVICE_RECEIPT_SCHEMA);
    assert_eq!(
        recovered.engine.verify_retirement_evidence(
            effect,
            claim(IOVA_CLAIM),
            DEVICE_EVIDENCE_RESET,
            &verifier,
            &wrong_subject,
        ),
        Err(CoreError::VerificationFailed)
    );
    assert_eq!(recovered.engine.projection_digest(), before);

    let stale_reset = verified_evidence_with_observation(
        &recovered,
        effect,
        claim(IOVA_CLAIM),
        DEVICE_EVIDENCE_RESET,
        cser_core::ReceiptBinding::new(
            cser_core::DEVICE_VERIFIER,
            cser_core::DEVICE_RECEIPT_SCHEMA,
        ),
        old_freshness,
        digest(41),
    );
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
        let permit = match recovered.output(Command::ReserveReuse {
            effect: reuse_effect,
            actor: reuse_actor,
            binding_generation: 1,
            claim: claim(4100 + offset),
            domain: DEVICE_DOMAIN,
            kind,
            scope: cser_core::ClaimScope::Device(cser_core::DeviceScopeId::new(1).unwrap()),
            resource: resource(resource_value),
            expected_generation: cser_core::ResourceGeneration::new(1).unwrap(),
            units: 1,
        }) {
            cser_core::TransitionOutput::ReusePermit(permit) => permit,
            other => panic!("expected reuse permit, got {other:?}"),
        };
        assert_eq!(permit.resource(), resource(resource_value));
        assert_eq!(permit.generation().get(), 2);
        assert_eq!(permit.freshness(), freshness(2, 1, 1, 2, 2));
        recovered.tx(permit.activate()).unwrap();
    }
}
