#[allow(dead_code)]
mod support;

use cser_core::{
    AuthorityState, BootGeneration, ChargeAccountId, ClaimId, ClaimScope, Command, CommandRequest,
    CoreError, CoreLimits, DEVICE_CLAIM_IOVA, DEVICE_DOMAIN, DEVICE_EVIDENCE_IOTLB,
    DEVICE_EVIDENCE_RESET, DEVICE_OBLIGATION_DMA, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER,
    DeviceGeneration, DeviceScopeId, Digest, EffectId, Engine, EvidenceChallenge, ExternalOutcome,
    Freshness, JournalGeneration, PrincipalId, PrincipalIncarnation, ReceiptVerifier,
    RegistryInstance, ResourceGeneration, ResourceId, SettlementClaim, SettlementState, SnapshotId,
    TransitionOutput, TransitionReceipt, TxError, VerificationError, VerifiedObservation,
    VerifierIdentity, WorldId, standard_catalog,
};
use cser_model::core_rebaseline_oracle::{
    DeviceOracle, OracleError, OracleSettlement, SettlementOracle,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawDeviceReceipt {
    effect: EffectId,
    claim: ClaimId,
    kind: cser_core::EvidenceKindId,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    subject: Freshness,
    observation: Freshness,
    digest: Digest,
}

#[derive(Clone, Copy, Debug)]
struct ExactDeviceVerifier {
    identity: VerifierIdentity,
}

impl ExactDeviceVerifier {
    fn new() -> Self {
        Self {
            identity: VerifierIdentity::new(DEVICE_VERIFIER, 1, DEVICE_RECEIPT_SCHEMA).unwrap(),
        }
    }
}

impl ReceiptVerifier for ExactDeviceVerifier {
    type Receipt = RawDeviceReceipt;

    fn identity(&self) -> VerifierIdentity {
        self.identity
    }

    fn verify(
        &self,
        challenge: &EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        if receipt.effect != challenge.effect()
            || receipt.claim != challenge.claim()
            || receipt.kind != challenge.kind()
            || receipt.resource != challenge.resource()
            || receipt.resource_generation != challenge.resource_generation()
            || receipt.subject != challenge.subject()
            || receipt.digest.is_zero()
        {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new(
            receipt.subject,
            receipt.observation,
            receipt.digest,
        ))
    }
}

struct Harness {
    engine: Engine,
    journal: Vec<u8>,
}

impl Harness {
    fn new() -> Self {
        Self {
            engine: Engine::new_scoped_legacy_compatibility(
                WorldId::new(1).unwrap(),
                standard_catalog(),
                CoreLimits::bounded_default(),
                freshness(1, 1, 1, 1, 1),
            ),
            journal: Vec::new(),
        }
    }

    fn tx<C: Into<Command>>(&mut self, command: C) -> Result<TransitionReceipt, CoreError> {
        let journal = &mut self.journal;
        self.engine
            .transact(command, |record| {
                journal.extend_from_slice(record.bytes());
                Ok::<(), ()>(())
            })
            .map_err(|error| match error {
                TxError::Core(error) => error,
                TxError::Journal(error) => CoreError::Journal(error),
                TxError::Persist(()) => unreachable!("memory journal cannot fail"),
            })
    }

    fn output<C: Into<Command>>(&mut self, command: C) -> TransitionOutput {
        self.tx(command).unwrap().into_output()
    }
}

#[derive(Clone, Copy)]
struct DeviceFixture {
    effect: EffectId,
    scope: DeviceScopeId,
    claim_a: ClaimId,
    resource_a: ResourceId,
    claim_b: ClaimId,
}

fn effect(root_value: u64) -> EffectId {
    EffectId::new(cser_core::RootId::new(root_value).unwrap(), 1).unwrap()
}

fn principal(id: u64, generation: u64) -> PrincipalIncarnation {
    PrincipalIncarnation::new(PrincipalId::new(id).unwrap(), generation).unwrap()
}

fn claim(value: u64) -> ClaimId {
    ClaimId::new(value).unwrap()
}

fn resource(value: u64) -> ResourceId {
    ResourceId::new(value).unwrap()
}

fn snapshot(value: u64) -> SnapshotId {
    SnapshotId::new(value).unwrap()
}

fn digest(value: u8) -> Digest {
    let mut bytes = [0; 32];
    bytes[0] = value;
    Digest::new(bytes)
}

fn freshness(boot: u64, registry: u64, binding: u64, device: u64, journal: u64) -> Freshness {
    Freshness::new(
        BootGeneration::new(boot).unwrap(),
        RegistryInstance::new(registry).unwrap(),
        binding,
        DeviceGeneration::new(device).unwrap(),
        JournalGeneration::new(journal).unwrap(),
    )
    .unwrap()
}

fn committed_reply(harness: &mut Harness, root_value: u64) -> (EffectId, PrincipalIncarnation) {
    let effect = effect(root_value);
    let origin = principal(root_value, 1);
    harness
        .tx(CommandRequest::CreateEstate {
            effect,
            origin,
            binding_generation: 1,
            domain: cser_core::REPLY_DOMAIN,
            obligation: cser_core::REPLY_OBLIGATION_PUBLICATION,
            charge_account: ChargeAccountId::new(root_value).unwrap(),
        })
        .unwrap();
    harness
        .tx(CommandRequest::AddClaim {
            effect,
            actor: origin,
            binding_generation: 1,
            claim: claim(root_value),
            domain: cser_core::REPLY_DOMAIN,
            kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: resource(root_value),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        })
        .unwrap();
    harness
        .tx(CommandRequest::PrepareEffect {
            effect,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    let intent = match harness.output(CommandRequest::RecordCommitIntent {
        effect,
        actor: origin,
        binding_generation: 1,
        operation: digest(10),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    let outcome = support::verified_commit_outcome_for_engine(
        &harness.engine,
        &intent,
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_COMMIT_RECEIPT_SCHEMA,
        ExternalOutcome::Success,
        digest(11),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    (effect, origin)
}

fn fence_and_rebind(
    harness: &mut Harness,
    effect: EffectId,
    crashed: PrincipalIncarnation,
    successor: PrincipalIncarnation,
    old_binding: u64,
    new_binding: u64,
    snapshot_value: u64,
) {
    harness
        .tx(CommandRequest::FenceIncarnation {
            root: effect.root(),
            crashed,
            binding_generation: old_binding,
        })
        .unwrap();
    let snapshot = snapshot(snapshot_value);
    let snapshot_record = harness
        .engine
        .snapshot_root(effect.root(), snapshot)
        .unwrap()
        .record();
    harness.tx(snapshot_record).unwrap();
    harness
        .tx(CommandRequest::Ready {
            root: effect.root(),
            snapshot,
            successor,
        })
        .unwrap();
    harness
        .tx(CommandRequest::Rebind {
            root: effect.root(),
            snapshot,
            successor,
            binding_generation: new_binding,
        })
        .unwrap();
}

fn open_reply(
    root_value: u64,
) -> (
    Harness,
    EffectId,
    PrincipalIncarnation,
    PrincipalIncarnation,
) {
    let mut harness = Harness::new();
    let (effect, origin) = committed_reply(&mut harness, root_value);
    let successor = principal(root_value, 2);
    fence_and_rebind(&mut harness, effect, origin, successor, 1, 2, root_value);
    (harness, effect, origin, successor)
}

fn settlement_claim(
    harness: &mut Harness,
    effect: EffectId,
    claimant: PrincipalIncarnation,
) -> SettlementClaim {
    match harness.output(CommandRequest::ClaimSettlement { effect, claimant }) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    }
}

fn normalize_settlement(engine: &Engine, effect: EffectId) -> OracleSettlement {
    let estate = engine.estate(effect).unwrap();
    if estate.authority == AuthorityState::Revoked {
        return OracleSettlement::Revoked;
    }
    match estate.settlement {
        SettlementState::Open { generation } => OracleSettlement::Open { generation },
        SettlementState::Claimed {
            claimant,
            generation,
        } => OracleSettlement::Claimed {
            claimant: claimant.generation(),
            generation,
        },
        SettlementState::ApplyIntentDurable {
            claimant,
            generation,
        } => OracleSettlement::ApplyIntentDurable {
            claimant: claimant.generation(),
            generation,
        },
        SettlementState::AppliedUnacknowledged {
            claimant,
            generation,
        } => OracleSettlement::AppliedUnacknowledged {
            claimant: claimant.generation(),
            generation,
        },
        SettlementState::ReconciliationRequired {
            generation,
            applied,
        } => OracleSettlement::ReconciliationRequired {
            generation,
            applied,
        },
        SettlementState::Settled => OracleSettlement::Settled,
        SettlementState::Revoked => OracleSettlement::Revoked,
        SettlementState::Unavailable | SettlementState::NotRequired => {
            panic!("test requires an open settlement gate")
        }
    }
}

fn assert_settlement(harness: &Harness, effect: EffectId, oracle: &SettlementOracle) {
    assert_eq!(
        normalize_settlement(&harness.engine, effect),
        oracle.projection()
    );
}

fn committed_device_fixture(harness: &mut Harness, root_value: u64) -> DeviceFixture {
    let effect = effect(root_value);
    let origin = principal(root_value, 1);
    let claim_a = claim(root_value * 10 + 1);
    let claim_b = claim(root_value * 10 + 2);
    let resource_a = resource(root_value * 10 + 1);
    let resource_b = resource(root_value * 10 + 2);
    let scope = DeviceScopeId::new(1).unwrap();
    harness
        .tx(CommandRequest::CreateEstate {
            effect,
            origin,
            binding_generation: 1,
            domain: DEVICE_DOMAIN,
            obligation: DEVICE_OBLIGATION_DMA,
            charge_account: ChargeAccountId::new(root_value).unwrap(),
        })
        .unwrap();
    for (claim, resource) in [(claim_a, resource_a), (claim_b, resource_b)] {
        harness
            .tx(CommandRequest::AddClaim {
                effect,
                actor: origin,
                binding_generation: 1,
                claim,
                domain: DEVICE_DOMAIN,
                kind: DEVICE_CLAIM_IOVA,
                scope: ClaimScope::Device(scope),
                resource,
                resource_generation: ResourceGeneration::new(1).unwrap(),
                units: 1,
            })
            .unwrap();
    }
    harness
        .tx(CommandRequest::PrepareEffect {
            effect,
            actor: origin,
            binding_generation: 1,
        })
        .unwrap();
    let intent = match harness.output(CommandRequest::RecordCommitIntent {
        effect,
        actor: origin,
        binding_generation: 1,
        operation: digest(70),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    let outcome = support::verified_commit_outcome_for_engine(
        &harness.engine,
        &intent,
        cser_core::DEVICE_VERIFIER,
        cser_core::DEVICE_COMMIT_RECEIPT_SCHEMA,
        ExternalOutcome::Success,
        digest(71),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    DeviceFixture {
        effect,
        scope,
        claim_a,
        resource_a,
        claim_b,
    }
}

fn verified_device_command(
    engine: &Engine,
    effect: EffectId,
    claim: ClaimId,
    kind: cser_core::EvidenceKindId,
    subject: Freshness,
    observation: Freshness,
    digest: Digest,
) -> Command {
    let challenge = engine.evidence_challenge(effect, claim, kind).unwrap();
    let receipt = RawDeviceReceipt {
        effect,
        claim,
        kind,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject,
        observation,
        digest,
    };
    engine
        .verify_retirement_evidence(effect, claim, kind, &ExactDeviceVerifier::new(), &receipt)
        .unwrap()
        .submit()
}

fn assert_device(harness: &Harness, fixture: DeviceFixture, oracle: &DeviceOracle) {
    assert_eq!(
        harness
            .engine
            .device_generation(fixture.scope)
            .unwrap()
            .get(),
        oracle.device_generation()
    );
    assert_eq!(
        harness
            .engine
            .check_reusable(fixture.resource_a, ResourceGeneration::new(1).unwrap())
            .is_err(),
        oracle.is_retained()
    );
}

#[test]
fn independent_oracle_matches_both_claim_revoke_linearizations() {
    for claim_first in [true, false] {
        let (mut harness, effect, _, successor) = open_reply(60 + u64::from(claim_first));
        let mut oracle = SettlementOracle::open(1);
        assert_settlement(&harness, effect, &oracle);

        if claim_first {
            let _claim = settlement_claim(&mut harness, effect, successor);
            oracle.claim(2).unwrap();
            assert_settlement(&harness, effect, &oracle);

            let authority_epoch = harness.engine.estate(effect).unwrap().authority_epoch;
            assert_eq!(
                harness.tx(CommandRequest::BeginRevoke {
                    effect,
                    expected_actor: successor,
                    binding_generation: 2,
                    authority_epoch,
                }),
                Err(CoreError::GateClaimed)
            );
            assert_eq!(oracle.begin_revoke(), Err(OracleError::GateClaimed));
        } else {
            let authority_epoch = harness.engine.estate(effect).unwrap().authority_epoch;
            harness
                .tx(CommandRequest::BeginRevoke {
                    effect,
                    expected_actor: successor,
                    binding_generation: 2,
                    authority_epoch,
                })
                .unwrap();
            oracle.begin_revoke().unwrap();
            assert_settlement(&harness, effect, &oracle);

            assert_eq!(
                harness.tx(CommandRequest::ClaimSettlement {
                    effect,
                    claimant: successor,
                }),
                Err(CoreError::GateClosed)
            );
            assert_eq!(oracle.claim(2), Err(OracleError::GateClosed));
        }
        assert_settlement(&harness, effect, &oracle);
    }
}

#[test]
fn independent_oracle_matches_second_crash_reconciliation() {
    let (mut harness, effect, _, successor) = open_reply(63);
    let mut oracle = SettlementOracle::open(1);
    let claim = settlement_claim(&mut harness, effect, successor);
    oracle.claim(2).unwrap();

    let claim = match harness.output(claim.record_apply_intent(digest(80)).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected intent-stage claim, got {other:?}"),
    };
    oracle.record_apply_intent(2).unwrap();
    assert_settlement(&harness, effect, &oracle);
    let _lost_with_crashed_process = claim;

    harness
        .tx(CommandRequest::FenceIncarnation {
            root: effect.root(),
            crashed: successor,
            binding_generation: 2,
        })
        .unwrap();
    oracle.crash();
    assert_settlement(&harness, effect, &oracle);

    let third = principal(63, 3);
    let recovery_snapshot = snapshot(630);
    let snapshot_record = harness
        .engine
        .snapshot_root(effect.root(), recovery_snapshot)
        .unwrap()
        .record();
    harness.tx(snapshot_record).unwrap();
    harness
        .tx(CommandRequest::Ready {
            root: effect.root(),
            snapshot: recovery_snapshot,
            successor: third,
        })
        .unwrap();
    harness
        .tx(CommandRequest::Rebind {
            root: effect.root(),
            snapshot: recovery_snapshot,
            successor: third,
            binding_generation: 3,
        })
        .unwrap();
    let reconciliation = settlement_claim(&mut harness, effect, third);
    oracle.claim(3).unwrap();
    assert_settlement(&harness, effect, &oracle);

    let rejected = reconciliation
        .record_apply_intent(digest(82))
        .expect_err("a durable prior intent requires reconciliation");
    assert_eq!(rejected.error(), &CoreError::WrongSettlementStage);
    assert_eq!(
        oracle.record_apply_intent(3),
        Err(OracleError::WrongSettlementStage)
    );
    let reconciliation = rejected.into_claim();

    let applied = support::verified_apply_completion_for_engine(
        &harness.engine,
        &reconciliation,
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_APPLY_RECEIPT_SCHEMA,
        digest(83),
    );
    let reconciliation = match harness.output(reconciliation.record_applied(applied).unwrap()) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected reconciled applied claim, got {other:?}"),
    };
    oracle.record_applied(3).unwrap();
    assert_settlement(&harness, effect, &oracle);

    let acknowledgement = support::verified_settlement_ack_for_engine(
        &harness.engine,
        &reconciliation,
        cser_core::REPLY_VERIFIER,
        cser_core::REPLY_SETTLEMENT_RECEIPT_SCHEMA,
        digest(84),
    );
    harness
        .tx(reconciliation.settle(acknowledgement).unwrap())
        .unwrap();
    oracle.settle(3).unwrap();
    assert_settlement(&harness, effect, &oracle);
}

#[test]
fn independent_oracle_matches_device_generation_freshness_orders() {
    for iotlb_first in [true, false] {
        let mut harness = Harness::new();
        let fixture = committed_device_fixture(&mut harness, 70 + u64::from(iotlb_first));
        let subject = freshness(1, 1, 1, 1, 1);
        let observation_two = freshness(1, 1, 1, 2, 1);
        let observation_three = freshness(1, 1, 1, 3, 1);
        let mut oracle = DeviceOracle::retained(1);

        let reset_a = verified_device_command(
            &harness.engine,
            fixture.effect,
            fixture.claim_a,
            DEVICE_EVIDENCE_RESET,
            subject,
            observation_two,
            digest(90),
        );
        harness.tx(reset_a).unwrap();
        oracle.advance_device(2).unwrap();
        oracle.submit_reset(1, 2).unwrap();
        assert_device(&harness, fixture, &oracle);

        let old_iotlb = verified_device_command(
            &harness.engine,
            fixture.effect,
            fixture.claim_a,
            DEVICE_EVIDENCE_IOTLB,
            subject,
            observation_two,
            digest(91),
        );
        let next_reset = verified_device_command(
            &harness.engine,
            fixture.effect,
            fixture.claim_b,
            DEVICE_EVIDENCE_RESET,
            subject,
            observation_three,
            digest(92),
        );

        if iotlb_first {
            harness.tx(old_iotlb).unwrap();
            oracle.submit_after_reset(1, 2).unwrap();
            harness.tx(next_reset).unwrap();
            oracle.advance_device(3).unwrap();
        } else {
            harness.tx(next_reset).unwrap();
            oracle.advance_device(3).unwrap();
            assert_eq!(harness.tx(old_iotlb), Err(CoreError::StaleEvidence));
            assert_eq!(
                oracle.submit_after_reset(1, 2),
                Err(OracleError::StaleEvidence)
            );
            assert_device(&harness, fixture, &oracle);

            let fresh_iotlb = verified_device_command(
                &harness.engine,
                fixture.effect,
                fixture.claim_a,
                DEVICE_EVIDENCE_IOTLB,
                subject,
                observation_three,
                digest(93),
            );
            harness.tx(fresh_iotlb).unwrap();
            oracle.submit_after_reset(1, 3).unwrap();
        }
        assert_device(&harness, fixture, &oracle);
    }
}
