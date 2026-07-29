#[allow(dead_code)]
mod support;

use cser_core::{
    CommandRequest as Command, CommitState, CoreError, CoreLimits, Digest, Engine, Freshness,
    JournalDecodeError, JournalRepair, OutcomeState, RecoveryAnchor, RecoveryAnchorError,
    SettlementState, TransitionOutput, TxError, scan_journal, standard_catalog,
};
use support::{
    Harness, charge, claim, digest, effect, freshness, principal, resource, resource_generation,
};

fn recover(
    bytes: &[u8],
    committed: Freshness,
    target: Freshness,
    minimum_revision: u64,
    expected_head: Digest,
) -> Result<cser_core::RecoveryReport, CoreError> {
    Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            committed,
            target,
            minimum_revision,
            expected_head,
        )
        .expect("test anchor must be structurally valid"),
        bytes,
    )
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

fn create_estate(root_value: u64) -> Command {
    Command::CreateEstate {
        effect: effect(root_value, 1),
        origin: principal(root_value, 1),
        binding_generation: 1,
        domain: cser_core::REPLY_DOMAIN,
        obligation: cser_core::REPLY_OBLIGATION_PUBLICATION,
        charge_account: charge(root_value),
    }
}

fn add_reply_claim(harness: &mut Harness, root_value: u64) {
    harness
        .tx(Command::AddClaim {
            effect: effect(root_value, 1),
            actor: principal(root_value, 1),
            binding_generation: 1,
            claim: claim(root_value),
            domain: cser_core::REPLY_DOMAIN,
            kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(root_value),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
}

#[test]
fn record_roundtrip_recovers_the_exact_acknowledged_chain_head() {
    let mut source = Harness::new();
    source.tx(create_estate(20)).unwrap();
    add_reply_claim(&mut source, 20);
    source
        .tx(Command::PrepareEffect {
            effect: effect(20, 1),
            actor: principal(20, 1),
            binding_generation: 1,
        })
        .unwrap();

    let scan = scan_journal(&source.journal).unwrap();
    assert_eq!(scan.torn_tail(), None);
    assert_eq!(scan.records().len(), 3);
    assert_eq!(
        scan.records()
            .iter()
            .flat_map(|record| record.bytes())
            .copied()
            .collect::<Vec<_>>(),
        source.journal
    );

    let report = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 1, 2),
            source.engine.revision(),
            source.engine.head(),
        )
        .unwrap(),
        &source.journal,
    )
    .unwrap();
    assert_eq!(report.acknowledged_revision(), source.engine.revision());
    assert_eq!(report.acknowledged_head(), source.engine.head());
    let replay = report.into_engine();
    assert_eq!(
        replay.estate(effect(20, 1)).unwrap().commit,
        CommitState::Prepared
    );
    assert_eq!(replay.estate(effect(20, 1)).unwrap().retained_claims, 1);
}

#[test]
fn incomplete_final_record_recovers_only_the_acknowledged_prefix_and_quarantines() {
    let mut source = Harness::new();
    let first = source.tx(create_estate(21)).unwrap();
    let first_len = source.journal.len();
    source
        .tx(Command::AddClaim {
            effect: effect(21, 1),
            actor: principal(21, 1),
            binding_generation: 1,
            claim: claim(21),
            domain: cser_core::REPLY_DOMAIN,
            kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(21),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    let full_len = source.journal.len();
    source.journal.truncate(full_len - 7);

    let target = freshness(2, 1, 1, 1, 2);
    let report = recover(
        &source.journal,
        freshness(1, 1, 1, 1, 1),
        target,
        first.revision(),
        first.head(),
    )
    .unwrap();
    assert_eq!(report.acknowledged_revision(), first.revision());
    assert_eq!(report.acknowledged_head(), first.head());
    assert_eq!(report.torn_tail(), Some(first_len));

    let mut engine = report.into_engine();
    assert!(engine.pressure().quarantined);
    assert_eq!(
        engine.journal_repair_required(),
        Some(JournalRepair::TornTail { offset: first_len })
    );
    assert_eq!(
        engine.transact_volatile(Command::PrepareEffect {
            effect: effect(21, 1),
            actor: principal(21, 1),
            binding_generation: 1,
        }),
        Err(CoreError::JournalRepairRequired)
    );
    assert_eq!(
        engine.transact_volatile(Command::CheckpointRecovery {
            boot: target.boot(),
            journal: target.journal(),
            device: target.device(),
        }),
        Err(CoreError::JournalRepairRequired)
    );

    let mut recovered_journal = source.journal[..first_len].to_vec();
    let report = recover(
        &recovered_journal,
        freshness(1, 1, 1, 1, 1),
        target,
        first.revision(),
        first.head(),
    )
    .unwrap();
    let mut engine = report.into_engine();
    assert_eq!(engine.journal_repair_required(), None);
    checkpoint(&mut engine, &mut recovered_journal, target);
    assert!(!engine.pressure().quarantined);
}

#[test]
fn corruption_in_a_complete_record_is_never_downgraded_to_a_torn_tail() {
    let mut source = Harness::new();
    source.tx(create_estate(22)).unwrap();
    let mut corrupt = source.journal.clone();
    let payload_byte = corrupt.len() - 33;
    corrupt[payload_byte] ^= 0x40;

    assert!(matches!(
        scan_journal(&corrupt),
        Err(JournalDecodeError::ChecksumMismatch { offset: 0 })
    ));
    assert!(matches!(
        recover(
            &corrupt,
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 1, 2),
            1,
            source.engine.head()
        ),
        Err(CoreError::Journal(JournalDecodeError::ChecksumMismatch {
            offset: 0
        }))
    ));
}

#[test]
fn recovery_anchor_requires_exact_catalog_head_and_advancing_epochs() {
    let catalog = standard_catalog().digest();
    let committed = freshness(1, 1, 1, 1, 1);
    let next = freshness(2, 1, 1, 1, 2);
    let head = digest(1);

    assert_eq!(
        RecoveryAnchor::from_trusted_provider(Digest::ZERO, committed, next, 1, head),
        Err(RecoveryAnchorError::ZeroDigest)
    );
    assert_eq!(
        RecoveryAnchor::from_trusted_provider(catalog, committed, next, 1, Digest::ZERO),
        Err(RecoveryAnchorError::InconsistentGenesis)
    );
    assert_eq!(
        RecoveryAnchor::from_trusted_provider(catalog, committed, next, 0, head),
        Err(RecoveryAnchorError::InconsistentGenesis)
    );
    assert!(
        RecoveryAnchor::from_trusted_provider(catalog, committed, next, 0, Digest::ZERO).is_ok()
    );
    assert_eq!(
        RecoveryAnchor::from_trusted_provider(
            catalog,
            committed,
            freshness(2, 2, 1, 1, 2),
            1,
            head,
        ),
        Err(RecoveryAnchorError::RegistryMismatch)
    );
    assert_eq!(
        RecoveryAnchor::from_trusted_provider(
            catalog,
            committed,
            freshness(2, 1, 2, 1, 2),
            1,
            head,
        ),
        Err(RecoveryAnchorError::BindingMismatch)
    );
    assert_eq!(
        RecoveryAnchor::from_trusted_provider(
            catalog,
            committed,
            freshness(1, 1, 1, 1, 2),
            1,
            head,
        ),
        Err(RecoveryAnchorError::NonAdvancingEpoch)
    );
}

#[test]
fn trusted_revision_head_and_freshness_anchors_reject_rollback() {
    let mut source = Harness::new();
    let first = source.tx(create_estate(23)).unwrap();
    let prefix_len = source.journal.len();
    add_reply_claim(&mut source, 23);
    let second_revision = source.engine.revision();
    let second_head = source.engine.head();

    assert_eq!(
        recover(
            &source.journal[..prefix_len],
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 1, 2),
            second_revision,
            first.head(),
        )
        .unwrap_err(),
        CoreError::RollbackDetected
    );
    assert_eq!(
        recover(
            &source.journal[..prefix_len],
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 1, 2),
            first.revision(),
            second_head,
        )
        .unwrap_err(),
        CoreError::RollbackDetected
    );
    assert_eq!(
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            freshness(1, 1, 1, 1, 1),
            freshness(1, 1, 1, 1, 2),
            second_revision,
            second_head,
        ),
        Err(RecoveryAnchorError::NonAdvancingEpoch)
    );
    assert_eq!(
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 1, 1),
            second_revision,
            second_head,
        ),
        Err(RecoveryAnchorError::NonAdvancingEpoch)
    );
    assert_eq!(
        Engine::recover(
            standard_catalog(),
            CoreLimits::bounded_default(),
            RecoveryAnchor::from_trusted_provider(
                standard_catalog().digest(),
                freshness(1, 2, 1, 1, 1),
                freshness(2, 2, 1, 1, 2),
                second_revision,
                second_head,
            )
            .unwrap(),
            &source.journal,
        )
        .unwrap_err(),
        CoreError::SchemaMismatch
    );
    assert_eq!(
        Engine::recover(
            standard_catalog(),
            CoreLimits::bounded_default(),
            RecoveryAnchor::from_trusted_provider(
                digest(254),
                freshness(1, 1, 1, 1, 1),
                freshness(2, 1, 1, 1, 2),
                second_revision,
                second_head,
            )
            .unwrap(),
            &source.journal,
        )
        .unwrap_err(),
        CoreError::SchemaMismatch
    );
    assert_eq!(
        recover(
            &source.journal,
            freshness(1, 1, 1, 2, 1),
            freshness(2, 1, 1, 2, 2),
            second_revision,
            second_head,
        )
        .unwrap_err(),
        CoreError::FreshnessRollback
    );

    let mut device_source = Harness::new();
    device_source.tx(create_estate(230)).unwrap();
    let first_recovery = freshness(2, 1, 1, 2, 2);
    let report = recover(
        &device_source.journal,
        freshness(1, 1, 1, 1, 1),
        first_recovery,
        device_source.engine.revision(),
        device_source.engine.head(),
    )
    .unwrap();
    let mut recovered = report.into_engine();
    checkpoint(&mut recovered, &mut device_source.journal, first_recovery);
    let target_with_older_device = freshness(3, 1, 1, 1, 3);
    assert_eq!(
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            first_recovery,
            target_with_older_device,
            recovered.revision(),
            recovered.head(),
        ),
        Err(RecoveryAnchorError::NonAdvancingEpoch)
    );
}

#[test]
fn trusted_head_recovers_before_complete_or_corrupt_unanchored_suffix() {
    let mut source = Harness::new();
    let first = source.tx(create_estate(231)).unwrap();
    let accepted_len = source.journal.len();
    add_reply_claim(&mut source, 231);

    for bytes in [source.journal.clone(), {
        let mut corrupt_suffix = source.journal.clone();
        let suffix_byte = accepted_len + 24;
        corrupt_suffix[suffix_byte] ^= 0x40;
        corrupt_suffix
    }] {
        let report = recover(
            &bytes,
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 1, 2),
            first.revision(),
            first.head(),
        )
        .unwrap();
        assert_eq!(report.acknowledged_revision(), first.revision());
        assert_eq!(report.acknowledged_head(), first.head());
        assert_eq!(
            report.journal_repair(),
            Some(JournalRepair::UnanchoredSuffix {
                offset: accepted_len
            })
        );
        assert_eq!(report.torn_tail(), None);

        let mut engine = report.into_engine();
        assert_eq!(engine.estate(effect(231, 1)).unwrap().claim_count, 0);
        assert_eq!(
            engine.journal_repair_required(),
            Some(JournalRepair::UnanchoredSuffix {
                offset: accepted_len
            })
        );
        assert_eq!(
            engine.transact_volatile(Command::AddClaim {
                effect: effect(231, 1),
                actor: principal(231, 1),
                binding_generation: 1,
                claim: claim(231),
                domain: cser_core::REPLY_DOMAIN,
                kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
                scope: cser_core::ClaimScope::Logical,
                resource: resource(231),
                resource_generation: resource_generation(1),
                units: 1,
            }),
            Err(CoreError::JournalRepairRequired)
        );
    }

    let mut corrupt_anchor = source.journal[..accepted_len].to_vec();
    corrupt_anchor[24] ^= 0x40;
    assert!(matches!(
        recover(
            &corrupt_anchor,
            freshness(1, 1, 1, 1, 1),
            freshness(2, 1, 1, 1, 2),
            first.revision(),
            first.head(),
        ),
        Err(CoreError::Journal(JournalDecodeError::ChecksumMismatch {
            offset: 0
        }))
    ));
}

#[test]
fn trusted_genesis_recovers_an_empty_prefix_and_rejects_unanchored_first_append() {
    let committed = freshness(1, 1, 1, 1, 1);
    let target = freshness(2, 1, 1, 1, 2);
    let genesis_anchor = || {
        RecoveryAnchor::from_trusted_provider(
            standard_catalog().digest(),
            committed,
            target,
            0,
            Digest::ZERO,
        )
        .unwrap()
    };

    let report = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        genesis_anchor(),
        &[],
    )
    .unwrap();
    assert_eq!(report.acknowledged_revision(), 0);
    assert_eq!(report.acknowledged_head(), Digest::ZERO);
    assert_eq!(report.journal_repair(), None);
    let mut journal = Vec::new();
    let mut engine = report.into_engine();
    assert_eq!(
        engine.transact_volatile(create_estate(232)),
        Err(CoreError::RecoveryPending)
    );
    checkpoint(&mut engine, &mut journal, target);
    assert_eq!(engine.revision(), 1);
    assert_ne!(engine.head(), Digest::ZERO);
    engine
        .transact(create_estate(232), |record| {
            journal.extend_from_slice(record.bytes());
            Ok::<(), ()>(())
        })
        .unwrap();

    let unanchored_first_append = journal.clone();
    let report = Engine::recover(
        standard_catalog(),
        CoreLimits::bounded_default(),
        genesis_anchor(),
        &unanchored_first_append,
    )
    .unwrap();
    assert_eq!(
        report.journal_repair(),
        Some(JournalRepair::UnanchoredSuffix { offset: 0 })
    );
    let mut engine = report.into_engine();
    assert_eq!(
        engine.transact_volatile(Command::CheckpointRecovery {
            boot: target.boot(),
            journal: target.journal(),
            device: target.device(),
        }),
        Err(CoreError::JournalRepairRequired)
    );
}

#[test]
fn ambiguous_persistence_failure_latches_the_engine_until_journal_recovery() {
    #[derive(Debug, Eq, PartialEq)]
    struct DiskFull;

    let mut engine = Engine::new(
        standard_catalog(),
        CoreLimits::bounded_default(),
        freshness(1, 1, 1, 1, 1),
    );
    let before_projection = engine.projection_digest();
    let before_revision = engine.revision();
    let before_head = engine.head();
    let mut rejected_record = Vec::new();
    let error = engine
        .transact(create_estate(24), |record| {
            rejected_record.extend_from_slice(record.bytes());
            Err(DiskFull)
        })
        .unwrap_err();
    assert_eq!(error, TxError::Persist(DiskFull));
    assert_eq!(engine.projection_digest(), before_projection);
    assert_eq!(engine.revision(), before_revision);
    assert_eq!(engine.head(), before_head);
    assert_eq!(engine.estate(effect(24, 1)), None);
    assert!(engine.persistence_recovery_required());
    assert!(engine.pressure().persistence_recovery_required);

    assert_eq!(
        engine.transact(create_estate(24), |_| Ok::<(), DiskFull>(())),
        Err(TxError::Core(CoreError::PersistenceRecoveryRequired))
    );

    let accepted = scan_journal(&rejected_record).unwrap();
    let candidate = accepted.records().last().unwrap();
    let target = freshness(2, 1, 1, 1, 2);
    let recovered = recover(
        &rejected_record,
        freshness(1, 1, 1, 1, 1),
        target,
        candidate.revision(),
        candidate.digest(),
    )
    .unwrap();
    assert_eq!(recovered.acknowledged_revision(), 1);
    assert_eq!(recovered.acknowledged_head(), candidate.digest());
    assert!(recovered.into_engine().estate(effect(24, 1)).is_some());
}

#[test]
fn crash_after_durable_commit_intent_recovers_as_indeterminate_without_reapply() {
    let mut source = Harness::new();
    let effect = effect(25, 1);
    source.tx(create_estate(25)).unwrap();
    add_reply_claim(&mut source, 25);
    source
        .tx(Command::PrepareEffect {
            effect,
            actor: principal(25, 1),
            binding_generation: 1,
        })
        .unwrap();
    let operation = digest(25);
    let intent_receipt = source
        .tx(Command::RecordCommitIntent {
            effect,
            actor: principal(25, 1),
            binding_generation: 1,
            operation,
        })
        .unwrap();
    assert!(matches!(
        intent_receipt.into_output(),
        TransitionOutput::CommitIntent(_)
    ));

    let target = freshness(2, 1, 1, 1, 2);
    let report = recover(
        &source.journal,
        freshness(1, 1, 1, 1, 1),
        target,
        source.engine.revision(),
        source.engine.head(),
    )
    .unwrap();
    let mut recovered = report.into_engine();
    assert_eq!(
        recovered.estate(effect).unwrap().commit,
        CommitState::CommitIntentDurable
    );
    checkpoint(&mut recovered, &mut source.journal, target);

    let estate = recovered.estate(effect).unwrap();
    assert_eq!(estate.commit, CommitState::Committed);
    assert_eq!(estate.outcome, OutcomeState::Indeterminate(operation));
    assert!(matches!(
        estate.settlement,
        SettlementState::Open { generation: 1 }
    ));

    let target = freshness(3, 1, 1, 1, 3);
    let report = recover(
        &source.journal,
        freshness(2, 1, 1, 1, 2),
        target,
        recovered.revision(),
        recovered.head(),
    )
    .unwrap();
    let replayed = report.into_engine();
    let estate = replayed.estate(effect).unwrap();
    assert_eq!(estate.commit, CommitState::Committed);
    assert_eq!(estate.outcome, OutcomeState::Indeterminate(operation));
    assert!(matches!(
        estate.settlement,
        SettlementState::Open { generation: 1 }
    ));
}

#[test]
fn fixture_recovers_and_reconciles_across_three_real_processes() {
    use std::{
        fs,
        process::Command as ProcessCommand,
        time::{SystemTime, UNIX_EPOCH},
    };

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "cser-restart-{}-{unique}.journal",
        std::process::id()
    ));
    let binary = env!("CARGO_BIN_EXE_cser-restart-fixture");

    let mut anchor: Option<(String, String)> = None;
    for phase in ["origin", "adopt", "reconcile"] {
        let mut process = ProcessCommand::new(binary);
        process.arg(phase).arg(&path);
        if let Some((revision, head)) = &anchor {
            process.arg(revision).arg(head);
        }
        let output = process.output().unwrap();
        assert!(
            output.status.success(),
            "phase {phase} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let mut fields = stdout.split_whitespace();
        let revision = fields
            .next()
            .unwrap_or_else(|| panic!("phase {phase} omitted anchor revision"));
        let head = fields
            .next()
            .unwrap_or_else(|| panic!("phase {phase} omitted anchor head"));
        assert!(
            fields.next().is_none(),
            "phase {phase} emitted an ambiguous anchor"
        );
        anchor = Some((revision.to_owned(), head.to_owned()));
        if phase == "origin" {
            let mut stale_head = head.as_bytes().to_vec();
            stale_head[0] = if stale_head[0] == b'0' { b'1' } else { b'0' };
            let stale_head = String::from_utf8(stale_head).unwrap();
            let rejected = ProcessCommand::new(binary)
                .arg("adopt")
                .arg(&path)
                .arg(revision)
                .arg(stale_head)
                .output()
                .unwrap();
            assert!(
                !rejected.status.success(),
                "adopt accepted a stale external head: stdout={} stderr={}",
                String::from_utf8_lossy(&rejected.stdout),
                String::from_utf8_lossy(&rejected.stderr)
            );
        }
    }

    let bytes = fs::read(&path).unwrap();
    let scan = scan_journal(&bytes).unwrap();
    assert!(scan.records().len() >= 18);
    assert_eq!(scan.torn_tail(), None);
    fs::remove_file(&path).unwrap();
}

#[cfg(feature = "std")]
#[test]
fn file_journal_requires_exact_recovery_coordinates_before_torn_tail_repair() {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use cser_core::std_support::FileJournal;

    let mut source = Harness::new();
    let first = source.tx(create_estate(27)).unwrap();
    let accepted_len = source.journal.len();
    source
        .tx(Command::AddClaim {
            effect: effect(27, 1),
            actor: principal(27, 1),
            binding_generation: 1,
            claim: claim(27),
            domain: cser_core::REPLY_DOMAIN,
            kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(27),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    source.journal.truncate(source.journal.len() - 9);

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "cser-torn-repair-{}-{unique}.journal",
        std::process::id()
    ));
    fs::write(&path, &source.journal).unwrap();

    let mut file = FileJournal::open(&path).unwrap();
    assert_eq!(file.torn_tail(), Some(accepted_len));
    assert_eq!(file.revision(), first.revision());
    assert_eq!(file.head(), first.head());
    assert!(
        file.repair_to_anchored_prefix(accepted_len, first.revision(), digest(250))
            .is_err()
    );
    file.repair_to_anchored_prefix(accepted_len, first.revision(), first.head())
        .unwrap();
    assert_eq!(file.torn_tail(), None);
    assert_eq!(fs::metadata(&path).unwrap().len(), accepted_len as u64);

    let target = freshness(2, 1, 1, 1, 2);
    let report = recover(
        &file.read_all().unwrap(),
        freshness(1, 1, 1, 1, 1),
        target,
        first.revision(),
        first.head(),
    )
    .unwrap();
    let mut engine = report.into_engine();
    engine
        .transact(
            Command::CheckpointRecovery {
                boot: target.boot(),
                journal: target.journal(),
                device: target.device(),
            },
            |record| file.append(record),
        )
        .unwrap();

    let final_bytes = file.read_all().unwrap();
    let scan = scan_journal(&final_bytes).unwrap();
    assert_eq!(scan.torn_tail(), None);
    assert_eq!(scan.records().last().unwrap().digest(), engine.head());
    fs::remove_file(&path).unwrap();
}
