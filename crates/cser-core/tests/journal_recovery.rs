#[allow(dead_code)]
mod support;

use cser_core::{
    CatalogSet, CommandRequest as Command, CommitState, CoreError, CoreLimits, Digest, Engine,
    Freshness, JournalDecodeError, JournalRepair, OutcomeState, RecoveryAnchor,
    RecoveryAnchorError, SettlementState, TransitionOutput, TxError, scan_journal,
    tool_dma_catalog,
};
use support::{
    EFFECT_COMMIT_RECEIPT_SCHEMA, EFFECT_COMPONENT, EFFECT_VERIFIER, Harness, admit_command, claim,
    digest, effect, executor, freshness, recovery_anchor, resource, resource_generation,
    verified_commit_outcome,
};

fn recover(
    bytes: &[u8],
    committed: Freshness,
    target: Freshness,
    minimum_revision: u64,
    expected_head: Digest,
    projection: Digest,
) -> Result<cser_core::RecoveryReport, CoreError> {
    let catalog = tool_dma_catalog();
    let catalog_set = CatalogSet::new(core::slice::from_ref(&catalog)).unwrap();
    Engine::recover(
        catalog_set,
        CoreLimits::bounded_default(),
        recovery_anchor(
            CatalogSet::new(core::slice::from_ref(&catalog))
                .unwrap()
                .digest(),
            committed,
            target,
            minimum_revision,
            expected_head,
            projection,
        ),
        bytes,
    )
}

fn tool_genesis_projection() -> Digest {
    Engine::new(
        support::test_world(),
        CatalogSet::new(&[tool_dma_catalog()]).unwrap(),
        CoreLimits::bounded_default(),
        freshness(1, 1, 1, 1),
    )
    .projection_digest()
}

fn checkpoint(engine: &mut Engine, journal: &mut Vec<u8>, target: Freshness) {
    engine
        .transact(
            Command::CheckpointRecovery {
                boot: target.boot(),
                journal: target.journal(),
                device: target.device(),
            },
            |record| {
                journal.extend_from_slice(record.bytes());
                Ok::<(), ()>(())
            },
        )
        .unwrap();
}

fn add_claim(harness: &mut Harness, value: u64) {
    harness
        .tx(Command::AddComponentClaim {
            effect: effect(value, 1),
            component: EFFECT_COMPONENT,
            actor: executor(value, 1),
            claim: claim(value),
            kind: support::EFFECT_CLAIM_KIND,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(value),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
}

fn prepare(harness: &mut Harness, value: u64) {
    harness
        .tx(Command::PrepareCompositeEffect {
            effect: effect(value, 1),
            actor: executor(value, 1),
        })
        .unwrap();
}

fn create_prepared(value: u64) -> Harness {
    let mut harness = Harness::new();
    harness.tx(admit_command(effect(value, 1), value)).unwrap();
    add_claim(&mut harness, value);
    prepare(&mut harness, value);
    harness
}

#[test]
fn record_roundtrip_recovers_the_exact_acknowledged_chain_head() {
    let source = create_prepared(20);
    let scan = scan_journal(&source.journal).unwrap();
    assert_eq!(scan.torn_tail(), None);
    assert_eq!(
        scan.records()
            .iter()
            .flat_map(|record| record.bytes())
            .copied()
            .collect::<Vec<_>>(),
        source.journal
    );

    let report = recover(
        &source.journal,
        freshness(1, 1, 1, 1),
        freshness(2, 1, 1, 2),
        source.engine.revision(),
        source.engine.head(),
        source.engine.projection_digest(),
    )
    .unwrap();
    assert_eq!(report.acknowledged_revision(), source.engine.revision());
    assert_eq!(report.acknowledged_head(), source.engine.head());
    let replay = report.into_engine();
    assert_eq!(
        replay
            .component(effect(20, 1), EFFECT_COMPONENT)
            .unwrap()
            .commit,
        CommitState::Prepared
    );
    assert_eq!(
        replay
            .component(effect(20, 1), EFFECT_COMPONENT)
            .unwrap()
            .retained_claims,
        1
    );
}

#[test]
fn current_recovery_rejects_a_recognized_old_journal_prefix() {
    let committed = freshness(1, 1, 1, 1);
    let target = freshness(2, 1, 1, 2);
    let anchor = recovery_anchor(
        CatalogSet::new(&[tool_dma_catalog()]).unwrap().digest(),
        committed,
        target,
        0,
        Digest::ZERO,
        tool_genesis_projection(),
    );
    let mut old = Vec::from(*b"CSERJR5\0");
    old.extend_from_slice(b"old journal payload");
    assert!(matches!(
        Engine::recover(
            CatalogSet::new(&[tool_dma_catalog()]).unwrap(),
            CoreLimits::bounded_default(),
            anchor,
            &old
        ),
        Err(CoreError::Journal(JournalDecodeError::UnsupportedVersion {
            version: 5
        }))
    ));
}

#[test]
fn incomplete_final_record_recovers_only_the_acknowledged_prefix_and_quarantines() {
    let mut source = Harness::new();
    source.tx(admit_command(effect(21, 1), 21)).unwrap();
    add_claim(&mut source, 21);
    let accepted = source.journal.len();
    let accepted_revision = source.engine.revision();
    let accepted_head = source.engine.head();
    let accepted_projection = source.engine.projection_digest();
    prepare(&mut source, 21);
    let mut torn = source.journal.clone();
    torn.truncate(torn.len() - 7);
    let report = recover(
        &torn,
        freshness(1, 1, 1, 1),
        freshness(2, 1, 1, 2),
        accepted_revision,
        accepted_head,
        accepted_projection,
    )
    .unwrap();
    // Anchored recovery deliberately stops at the trusted head. It does not
    // inspect attacker-controlled residue merely to distinguish a torn write
    // from another unanchored suffix.
    assert_eq!(
        report.journal_repair(),
        Some(JournalRepair::UnanchoredSuffix { offset: accepted })
    );
    let mut engine = report.into_engine();
    assert!(engine.pressure().quarantined);
    assert_eq!(
        engine.transact_volatile(Command::PrepareCompositeEffect {
            effect: effect(21, 1),
            actor: executor(21, 1),
        }),
        Err(CoreError::JournalRepairRequired)
    );

    let mut repaired_journal = torn[..accepted].to_vec();
    // The accepted prefix is the source journal minus the incomplete tail.
    let accepted_prefix = scan_journal(&repaired_journal).unwrap();
    let accepted_record = accepted_prefix.records().last().unwrap();
    let mut engine = recover(
        &repaired_journal,
        freshness(1, 1, 1, 1),
        freshness(2, 1, 1, 2),
        accepted_record.revision(),
        accepted_record.digest(),
        accepted_projection,
    )
    .unwrap()
    .into_engine();
    checkpoint(&mut engine, &mut repaired_journal, freshness(2, 1, 1, 2));
    assert!(!engine.pressure().quarantined);
}

#[test]
fn corruption_in_a_complete_record_is_never_downgraded_to_a_torn_tail() {
    let source = create_prepared(22);
    let mut corrupt = source.journal.clone();
    corrupt[24] ^= 0x40;
    assert!(matches!(
        scan_journal(&corrupt),
        Err(JournalDecodeError::ChecksumMismatch { offset: 0 })
    ));
    assert!(matches!(
        recover(
            &corrupt,
            freshness(1, 1, 1, 1),
            freshness(2, 1, 1, 2),
            1,
            source.engine.head(),
            source.engine.projection_digest(),
        ),
        Err(CoreError::Journal(JournalDecodeError::ChecksumMismatch {
            offset: 0
        }))
    ));
}

#[test]
fn trusted_revision_head_and_freshness_anchors_reject_rollback() {
    let source = create_prepared(23);
    let scan = scan_journal(&source.journal).unwrap();
    let first = &scan.records()[0];
    assert_eq!(
        recover(
            &source.journal[..source.journal.len() / 2],
            freshness(1, 1, 1, 1),
            freshness(2, 1, 1, 2),
            source.engine.revision(),
            source.engine.head(),
            source.engine.projection_digest(),
        )
        .unwrap_err(),
        CoreError::RollbackDetected
    );
    assert_eq!(
        RecoveryAnchor::from_trusted_provider(
            support::recovery_binding(
                CatalogSet::new(&[tool_dma_catalog()]).unwrap().digest(),
                freshness(1, 1, 1, 1),
            ),
            freshness(1, 1, 1, 1),
            freshness(1, 1, 1, 2),
            first.revision(),
            first.digest(),
            source.engine.projection_digest(),
        ),
        Err(RecoveryAnchorError::NonAdvancingEpoch)
    );
}

#[test]
fn durable_commit_intent_recovers_as_indeterminate_without_reapply() {
    let mut source = create_prepared(25);
    let intent = match source.output(Command::RecordComponentCommitIntent {
        effect: effect(25, 1),
        component: EFFECT_COMPONENT,
        actor: executor(25, 1),
        operation: digest(25),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    let report = recover(
        &source.journal,
        freshness(1, 1, 1, 1),
        freshness(2, 1, 1, 2),
        source.engine.revision(),
        source.engine.head(),
        source.engine.projection_digest(),
    )
    .unwrap();
    let recovered = report.into_engine();
    assert_eq!(
        recovered
            .component(effect(25, 1), EFFECT_COMPONENT)
            .unwrap()
            .commit,
        CommitState::CommitIntentDurable
    );
    let outcome = verified_commit_outcome(
        &source,
        &intent,
        EFFECT_VERIFIER,
        EFFECT_COMMIT_RECEIPT_SCHEMA,
        cser_core::ExternalOutcome::Success,
        digest(26),
    );
    source.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    let effect = source
        .engine
        .component(effect(25, 1), EFFECT_COMPONENT)
        .unwrap();
    assert_eq!(effect.outcome, OutcomeState::KnownSuccess(digest(26)));
    assert!(matches!(effect.settlement, SettlementState::Open { .. }));
}

#[test]
fn recovery_anchor_rejects_wrong_catalog_and_nonadvancing_freshness() {
    let source = create_prepared(26);
    let committed = freshness(1, 1, 1, 1);
    let target = freshness(2, 1, 1, 2);
    let wrong = recovery_anchor(
        digest(254),
        committed,
        target,
        source.engine.revision(),
        source.engine.head(),
        source.engine.projection_digest(),
    );
    assert_eq!(
        Engine::recover(
            CatalogSet::new(&[tool_dma_catalog()]).unwrap(),
            CoreLimits::bounded_default(),
            wrong,
            &source.journal
        )
        .unwrap_err(),
        CoreError::SchemaMismatch
    );
    assert_eq!(
        RecoveryAnchor::from_trusted_provider(
            support::recovery_binding(
                CatalogSet::new(&[tool_dma_catalog()]).unwrap().digest(),
                committed,
            ),
            committed,
            freshness(1, 1, 1, 2),
            source.engine.revision(),
            source.engine.head(),
            source.engine.projection_digest(),
        ),
        Err(RecoveryAnchorError::NonAdvancingEpoch)
    );
}

#[test]
fn persistence_failure_latches_until_exact_recovery() {
    #[derive(Debug, Eq, PartialEq)]
    struct DiskFull;

    let mut source = Harness::new();
    let before = source.engine.projection_digest();
    let mut rejected = Vec::new();
    let error = source
        .engine
        .transact(admit_command(effect(27, 1), 27), |record| {
            rejected.extend_from_slice(record.bytes());
            Err::<(), _>(DiskFull)
        })
        .unwrap_err();
    assert_eq!(error, TxError::Persist(DiskFull));
    assert_eq!(source.engine.projection_digest(), before);
    assert!(source.engine.persistence_recovery_required());
    assert_eq!(
        source
            .engine
            .transact(admit_command(effect(27, 1), 27), |_| Ok::<(), DiskFull>(())),
        Err(TxError::Core(CoreError::PersistenceRecoveryRequired))
    );
    let scan = scan_journal(&rejected).unwrap();
    assert_eq!(scan.records().len(), 1);
}
