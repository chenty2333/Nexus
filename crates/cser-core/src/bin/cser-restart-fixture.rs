// SPDX-License-Identifier: MPL-2.0

use std::{env, path::Path, process};

use cser_core::{
    BootGeneration, ChargeAccountId, ClaimId, Command as AuthorizedCommand,
    CommandRequest as Command, CoreError, CoreLimits, DeviceGeneration, Digest, EffectFactKind,
    EffectId, EffectReceiptVerifier, Engine, ExternalOutcome, Freshness, JournalGeneration,
    PrincipalId, PrincipalIncarnation, ReceiptVerifier, RecoveryAnchor, RegistryInstance,
    ResourceGeneration, ResourceId, RetirementState, RootId, SettlementState, SnapshotId,
    TransitionOutput, TxError, VerificationError, VerifiedEffectObservation, VerifiedObservation,
    VerifierIdentity, standard_catalog,
    std_support::{FileJournal, read_all},
};

const ROOT_VALUE: u64 = 900;

#[derive(Clone, Copy)]
struct FixtureReplyReceipt {
    effect: EffectId,
    claim: ClaimId,
    resource: ResourceId,
    resource_generation: ResourceGeneration,
    subject: Freshness,
    observation: Freshness,
    digest: Digest,
}

struct FixtureReplyVerifier;

impl ReceiptVerifier for FixtureReplyVerifier {
    type Receipt = FixtureReplyReceipt;

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new(
            cser_core::REPLY_VERIFIER,
            1,
            cser_core::REPLY_RECEIPT_SCHEMA,
        )
        .unwrap()
    }

    fn verify(
        &self,
        challenge: &cser_core::EvidenceChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        if receipt.effect != challenge.effect()
            || receipt.claim != challenge.claim()
            || receipt.resource != challenge.resource()
            || receipt.resource_generation != challenge.resource_generation()
            || receipt.subject != challenge.subject()
            || receipt.observation != challenge.current_observation()
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

#[derive(Clone, Copy)]
struct FixtureEffectReceipt {
    kind: EffectFactKind,
    effect: EffectId,
    domain: cser_core::DomainId,
    obligation: cser_core::ObligationKindId,
    actor: PrincipalIncarnation,
    generation: u64,
    nonce: u64,
    operation: Digest,
    predecessor: Option<Digest>,
    freshness: Freshness,
    digest: Digest,
    outcome: Option<ExternalOutcome>,
}

struct FixtureEffectVerifier {
    schema: cser_core::ReceiptSchemaId,
}

impl EffectReceiptVerifier for FixtureEffectVerifier {
    type Receipt = FixtureEffectReceipt;

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new(cser_core::REPLY_VERIFIER, 1, self.schema).unwrap()
    }

    fn verify(
        &self,
        challenge: &cser_core::EffectFactChallenge,
        receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        if receipt.kind != challenge.kind()
            || receipt.effect != challenge.effect()
            || receipt.domain != challenge.domain()
            || receipt.obligation != challenge.obligation()
            || receipt.actor != challenge.actor()
            || receipt.generation != challenge.generation()
            || receipt.nonce != challenge.nonce()
            || receipt.operation != challenge.operation()
            || receipt.predecessor != challenge.predecessor()
            || receipt.freshness != challenge.current_observation()
            || receipt.digest.is_zero()
        {
            return Err(VerificationError::Rejected);
        }
        match (receipt.kind, receipt.outcome) {
            (EffectFactKind::CommitOutcome, Some(outcome)) => Ok(
                VerifiedEffectObservation::commit(receipt.freshness, outcome, receipt.digest),
            ),
            (EffectFactKind::ApplyCompleted | EffectFactKind::SettlementAcknowledged, None) => Ok(
                VerifiedEffectObservation::fact(receipt.freshness, receipt.digest),
            ),
            _ => Err(VerificationError::Rejected),
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let phase = args.next().ok_or_else(|| {
        "usage: cser-restart-fixture origin <journal> | \
         cser-restart-fixture <adopt|reconcile> <journal> <revision> <head>"
            .to_owned()
    })?;
    let path = args
        .next()
        .ok_or_else(|| "missing journal path".to_owned())?;
    match phase.as_str() {
        "origin" => {
            if args.next().is_some() {
                return Err("origin does not accept a recovery anchor".to_owned());
            }
            origin(Path::new(&path))
        }
        "adopt" | "reconcile" => {
            let revision = args
                .next()
                .ok_or_else(|| "missing trusted minimum revision".to_owned())?
                .parse::<u64>()
                .map_err(|_| "invalid trusted minimum revision".to_owned())?;
            let head = parse_digest(
                &args
                    .next()
                    .ok_or_else(|| "missing trusted expected head".to_owned())?,
            )?;
            if args.next().is_some() {
                return Err("unexpected extra argument".to_owned());
            }
            if phase == "adopt" {
                adopt(Path::new(&path), revision, head)
            } else {
                reconcile(Path::new(&path), revision, head)
            }
        }
        other => Err(format!("unknown phase {other}")),
    }
}

fn origin(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Err("origin requires a new journal".to_owned());
    }
    let mut file = FileJournal::open(path).map_err(io_error)?;
    let mut engine = Engine::new(
        standard_catalog(),
        CoreLimits::bounded_default(),
        freshness(1, 1),
    );
    tx(
        &mut engine,
        &mut file,
        Command::CreateEstate {
            effect: effect(),
            origin: principal(1),
            binding_generation: 1,
            domain: cser_core::REPLY_DOMAIN,
            obligation: cser_core::REPLY_OBLIGATION_PUBLICATION,
            charge_account: ChargeAccountId::new(ROOT_VALUE).unwrap(),
        },
    )?;
    tx(
        &mut engine,
        &mut file,
        Command::AddClaim {
            effect: effect(),
            actor: principal(1),
            binding_generation: 1,
            claim: claim(),
            domain: cser_core::REPLY_DOMAIN,
            kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(),
            resource_generation: cser_core::ResourceGeneration::new(1).unwrap(),
            units: 1,
        },
    )?;
    tx(
        &mut engine,
        &mut file,
        Command::PrepareEffect {
            effect: effect(),
            actor: principal(1),
            binding_generation: 1,
        },
    )?;
    let intent = match tx(
        &mut engine,
        &mut file,
        Command::RecordCommitIntent {
            effect: effect(),
            actor: principal(1),
            binding_generation: 1,
            operation: digest(10),
        },
    )?
    .into_output()
    {
        TransitionOutput::CommitIntent(intent) => intent,
        other => return Err(format!("expected commit intent, got {other:?}")),
    };
    let challenge = engine
        .commit_outcome_challenge(&intent)
        .map_err(core_error)?;
    let receipt = fixture_effect_receipt(challenge, digest(11), Some(ExternalOutcome::Success));
    let outcome = engine
        .verify_commit_outcome(
            &intent,
            &FixtureEffectVerifier {
                schema: cser_core::REPLY_COMMIT_RECEIPT_SCHEMA,
            },
            &receipt,
        )
        .map_err(core_error)?;
    tx(
        &mut engine,
        &mut file,
        intent
            .acknowledge(outcome)
            .map_err(|error| core_error(error.error().clone()))?,
    )?;
    publish_anchor(&engine);
    Ok(())
}

fn adopt(path: &Path, minimum_revision: u64, expected_head: Digest) -> Result<(), String> {
    let bytes = read_all(path).map_err(io_error)?;
    let target = freshness(2, 2);
    let catalog = standard_catalog();
    let anchor = RecoveryAnchor::from_trusted_provider(
        catalog.digest(),
        freshness(1, 1),
        target,
        minimum_revision,
        expected_head,
    )
    .map_err(|error| format!("invalid recovery anchor: {error:?}"))?;
    let report = Engine::recover(catalog, CoreLimits::bounded_default(), anchor, &bytes)
        .map_err(core_error)?;
    let mut engine = report.into_engine();
    let mut file = FileJournal::open(path).map_err(io_error)?;
    checkpoint(&mut engine, &mut file, target)?;
    recover_lane(&mut engine, &mut file, 1, principal(2), 2)?;
    let settlement = match tx(
        &mut engine,
        &mut file,
        Command::ClaimSettlement {
            effect: effect(),
            claimant: principal(2),
        },
    )?
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => return Err(format!("expected settlement claim, got {other:?}")),
    };
    tx(
        &mut engine,
        &mut file,
        settlement
            .record_apply_intent(digest(20))
            .map_err(claim_error)?,
    )?;
    publish_anchor(&engine);
    Ok(())
}

fn reconcile(path: &Path, minimum_revision: u64, expected_head: Digest) -> Result<(), String> {
    let bytes = read_all(path).map_err(io_error)?;
    let target = freshness(3, 3);
    let catalog = standard_catalog();
    let anchor = RecoveryAnchor::from_trusted_provider(
        catalog.digest(),
        freshness(2, 2),
        target,
        minimum_revision,
        expected_head,
    )
    .map_err(|error| format!("invalid recovery anchor: {error:?}"))?;
    let report = Engine::recover(catalog, CoreLimits::bounded_default(), anchor, &bytes)
        .map_err(core_error)?;
    let mut engine = report.into_engine();
    let mut file = FileJournal::open(path).map_err(io_error)?;
    checkpoint(&mut engine, &mut file, target)?;
    assert!(matches!(
        engine.estate(effect()).unwrap().settlement,
        SettlementState::ReconciliationRequired {
            generation: 2,
            applied: false
        }
    ));
    recover_lane(&mut engine, &mut file, 2, principal(3), 3)?;
    let settlement = match tx(
        &mut engine,
        &mut file,
        Command::ClaimSettlement {
            effect: effect(),
            claimant: principal(3),
        },
    )?
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => return Err(format!("expected reconciliation claim, got {other:?}")),
    };
    let rejected = settlement.record_apply_intent(digest(21)).unwrap_err();
    if rejected.error() != &CoreError::WrongSettlementStage {
        return Err(format!("unexpected local claim error: {rejected:?}"));
    }
    let settlement = rejected.into_claim();
    let challenge = engine
        .apply_completion_challenge(&settlement)
        .map_err(core_error)?;
    let receipt = fixture_effect_receipt(challenge, digest(22), None);
    let applied = engine
        .verify_apply_completion(
            &settlement,
            &FixtureEffectVerifier {
                schema: cser_core::REPLY_APPLY_RECEIPT_SCHEMA,
            },
            &receipt,
        )
        .map_err(core_error)?;
    let settlement = match tx(
        &mut engine,
        &mut file,
        settlement.record_applied(applied).map_err(claim_error)?,
    )?
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => return Err(format!("expected reconciled claim, got {other:?}")),
    };
    let challenge = engine
        .settlement_ack_challenge(&settlement)
        .map_err(core_error)?;
    let receipt = fixture_effect_receipt(challenge, digest(23), None);
    let acknowledgement = engine
        .verify_settlement_ack(
            &settlement,
            &FixtureEffectVerifier {
                schema: cser_core::REPLY_SETTLEMENT_RECEIPT_SCHEMA,
            },
            &receipt,
        )
        .map_err(core_error)?;
    tx(
        &mut engine,
        &mut file,
        settlement.settle(acknowledgement).map_err(claim_error)?,
    )?;
    let challenge = engine
        .evidence_challenge(effect(), claim(), cser_core::REPLY_EVIDENCE_PUBLICATION_ACK)
        .map_err(core_error)?;
    let receipt = FixtureReplyReceipt {
        effect: effect(),
        claim: claim(),
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: challenge.subject(),
        observation: challenge.current_observation(),
        digest: digest(24),
    };
    let evidence = engine
        .verify_retirement_evidence(
            effect(),
            claim(),
            cser_core::REPLY_EVIDENCE_PUBLICATION_ACK,
            &FixtureReplyVerifier,
            &receipt,
        )
        .map_err(core_error)?;
    tx(&mut engine, &mut file, evidence.submit())?;
    let estate = engine
        .estate(effect())
        .ok_or_else(|| "missing recovered estate".to_owned())?;
    if estate.settlement != SettlementState::Settled
        || estate.retirement != RetirementState::Retired
        || engine.pressure().quarantined
        || engine
            .check_reusable(resource(), cser_core::ResourceGeneration::new(1).unwrap())
            .is_err()
    {
        return Err(format!("unexpected final projection: {estate:?}"));
    }
    publish_anchor(&engine);
    Ok(())
}

fn recover_lane(
    engine: &mut Engine,
    file: &mut FileJournal,
    snapshot_value: u64,
    successor: PrincipalIncarnation,
    binding_generation: u64,
) -> Result<(), String> {
    let snapshot = SnapshotId::new(snapshot_value).unwrap();
    let snapshot_record = engine
        .snapshot_root(root(), snapshot)
        .map_err(core_error)?
        .record();
    tx(engine, file, snapshot_record)?;
    tx(
        engine,
        file,
        Command::Ready {
            root: root(),
            snapshot,
            successor,
        },
    )?;
    tx(
        engine,
        file,
        Command::Rebind {
            root: root(),
            snapshot,
            successor,
            binding_generation,
        },
    )?;
    Ok(())
}

fn checkpoint(
    engine: &mut Engine,
    file: &mut FileJournal,
    target: Freshness,
) -> Result<(), String> {
    tx(
        engine,
        file,
        Command::CheckpointRecovery {
            boot: target.boot(),
            journal: target.journal(),
            device: target.device(),
        },
    )?;
    Ok(())
}

fn tx<C>(
    engine: &mut Engine,
    file: &mut FileJournal,
    command: C,
) -> Result<cser_core::TransitionReceipt, String>
where
    C: Into<AuthorizedCommand>,
{
    engine
        .transact(command, |record| file.append(record))
        .map_err(|error| match error {
            TxError::Core(error) => core_error(error),
            TxError::Journal(error) => format!("journal error: {error:?}"),
            TxError::Persist(error) => io_error(error),
        })
}

fn fixture_effect_receipt(
    challenge: cser_core::EffectFactChallenge,
    digest: Digest,
    outcome: Option<ExternalOutcome>,
) -> FixtureEffectReceipt {
    FixtureEffectReceipt {
        kind: challenge.kind(),
        effect: challenge.effect(),
        domain: challenge.domain(),
        obligation: challenge.obligation(),
        actor: challenge.actor(),
        generation: challenge.generation(),
        nonce: challenge.nonce(),
        operation: challenge.operation(),
        predecessor: challenge.predecessor(),
        freshness: challenge.current_observation(),
        digest,
        outcome,
    }
}

fn freshness(boot: u64, journal: u64) -> Freshness {
    Freshness::new(
        BootGeneration::new(boot).unwrap(),
        RegistryInstance::new(1).unwrap(),
        1,
        DeviceGeneration::new(1).unwrap(),
        JournalGeneration::new(journal).unwrap(),
    )
    .unwrap()
}

fn root() -> RootId {
    RootId::new(ROOT_VALUE).unwrap()
}

fn effect() -> EffectId {
    EffectId::new(root(), 1).unwrap()
}

fn principal(generation: u64) -> PrincipalIncarnation {
    PrincipalIncarnation::new(PrincipalId::new(ROOT_VALUE).unwrap(), generation).unwrap()
}

fn claim() -> ClaimId {
    ClaimId::new(ROOT_VALUE).unwrap()
}

fn resource() -> ResourceId {
    ResourceId::new(ROOT_VALUE).unwrap()
}

fn digest(value: u8) -> Digest {
    let mut bytes = [0; 32];
    bytes[0] = value;
    Digest::new(bytes)
}

fn publish_anchor(engine: &Engine) {
    println!("{} {}", engine.revision(), encode_digest(engine.head()));
}

fn encode_digest(digest: Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest.bytes() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn parse_digest(encoded: &str) -> Result<Digest, String> {
    if encoded.len() != 64 {
        return Err("trusted expected head must contain exactly 64 hex digits".to_owned());
    }
    let mut bytes = [0; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = parse_hex_digit(pair[0])?;
        let low = parse_hex_digit(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    let digest = Digest::new(bytes);
    if digest.is_zero() {
        return Err("trusted expected head cannot be zero".to_owned());
    }
    Ok(digest)
}

fn parse_hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("trusted expected head contains non-hex data".to_owned()),
    }
}

fn core_error(error: CoreError) -> String {
    format!("core error: {error:?}")
}

fn claim_error(error: cser_core::ClaimUseError) -> String {
    format!("claim error: {error:?}")
}

fn io_error(error: std::io::Error) -> String {
    format!("I/O error: {error}")
}
