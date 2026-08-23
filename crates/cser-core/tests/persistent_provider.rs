#[allow(dead_code)]
mod support;

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use cser_core::{
    AGENT_COMPONENT_DMA, CatalogSet, ClaimScope, CommandRequest as Command,
    ComponentProviderBinding, CoordinatedPersistence, CoreError, CoreLimits, DEVICE_CLAIM_IOVA,
    DEVICE_EVIDENCE_IOTLB, DEVICE_EVIDENCE_RESET, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER,
    DMA_ARENA_REUSE_COMPOSITE, DeviceGeneration, DurableJournalBackend, Engine, Freshness,
    JournalRepair, RecoveryBinding, RecoveryLease, RecoveryProfile, TrustedAnchorBackend,
    TrustedAnchorSnapshot, TxError, WorldId, standard_catalog,
    std_support::{FileJournal, HostAnchorFailpoint, HostFileTrustedAnchor},
};
use support::{
    ExactTestVerifier, TestReceipt, charge, claim, digest, effect, executor, freshness,
    genesis_projection, provider, recovery_binding, register_provider_command, resource,
    resource_generation,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);
const CHILD_MODE: &str = "NEXUS_CSER_PERSISTENCE_CHILD";
const CHILD_DIRECTORY: &str = "NEXUS_CSER_PERSISTENCE_DIR";

struct TempStore {
    directory: PathBuf,
}

impl TempStore {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "nexus-cser-persistence-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        Self { directory }
    }

    fn journal(&self) -> PathBuf {
        self.directory.join("journal.bin")
    }

    fn anchor(&self) -> PathBuf {
        self.directory.join("anchor.bin")
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn binding() -> RecoveryBinding {
    recovery_binding(
        CatalogSet::new(&[standard_catalog()]).unwrap().digest(),
        freshness(1, 1, 1, 1),
    )
}

fn open_anchor(path: &Path) -> HostFileTrustedAnchor {
    HostFileTrustedAnchor::open_or_initialize(
        path,
        binding(),
        freshness(1, 1, 1, 1),
        genesis_projection(),
    )
    .unwrap()
}

#[derive(Clone, Debug)]
struct AnchorFailpointController(Arc<Mutex<HostAnchorFailpoint>>);

impl AnchorFailpointController {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(HostAnchorFailpoint::None)))
    }

    fn arm(&self, failpoint: HostAnchorFailpoint) {
        *self.0.lock().unwrap() = failpoint;
    }

    fn take(&self) -> HostAnchorFailpoint {
        core::mem::replace(&mut *self.0.lock().unwrap(), HostAnchorFailpoint::None)
    }
}

#[derive(Debug)]
struct ControlledHostAnchor {
    inner: HostFileTrustedAnchor,
    controller: AnchorFailpointController,
}

impl ControlledHostAnchor {
    fn new(inner: HostFileTrustedAnchor, controller: AnchorFailpointController) -> Self {
        Self { inner, controller }
    }

    fn inject(&mut self) {
        self.inner.set_failpoint(self.controller.take());
    }
}

impl TrustedAnchorBackend for ControlledHostAnchor {
    type Error = cser_core::std_support::HostAnchorError;

    fn reserve_recovery_epoch(
        &mut self,
        binding: RecoveryBinding,
        observed_device: DeviceGeneration,
    ) -> Result<RecoveryLease, Self::Error> {
        self.inject();
        self.inner.reserve_recovery_epoch(binding, observed_device)
    }

    fn compare_and_advance(
        &mut self,
        expected: TrustedAnchorSnapshot,
        replacement: TrustedAnchorSnapshot,
    ) -> Result<(), Self::Error> {
        self.inject();
        self.inner.compare_and_advance(expected, replacement)
    }
}

#[derive(Debug)]
struct Reopened {
    engine: Engine,
    persistence: CoordinatedPersistence<FileJournal, ControlledHostAnchor>,
    anchor_failpoint: AnchorFailpointController,
    target: Freshness,
    observed_repair: Option<JournalRepair>,
}

fn cold_reopen(directory: &Path, observed_device: u64) -> Result<Reopened, CoreError> {
    let anchor_path = directory.join("anchor.bin");
    let journal_path = directory.join("journal.bin");
    let anchor_failpoint = AnchorFailpointController::new();
    let mut anchor = ControlledHostAnchor::new(open_anchor(&anchor_path), anchor_failpoint.clone());
    let lease = anchor
        .reserve_recovery_epoch(binding(), DeviceGeneration::new(observed_device).unwrap())
        .unwrap();
    let committed = lease.committed();
    let target = lease.next_freshness();

    let mut journal = if journal_path.exists() {
        FileJournal::open_anchored(&journal_path, committed.revision(), committed.head())
            .map_err(|_| CoreError::RollbackDetected)?
    } else {
        FileJournal::open(&journal_path).unwrap()
    };
    let observed_repair = journal.journal_repair();
    if let Some(repair) = observed_repair {
        journal
            .repair_to_anchored_prefix(repair.offset(), committed.revision(), committed.head())
            .unwrap();
    }
    let bytes = journal.read_all().unwrap();
    let persistence = CoordinatedPersistence::from_recovery_lease(journal, anchor, &lease);
    let engine = Engine::recover(
        CatalogSet::new(&[standard_catalog()]).unwrap(),
        CoreLimits::bounded_default(),
        lease.into_recovery_anchor().unwrap(),
        &bytes,
    )?
    .into_engine();
    Ok(Reopened {
        engine,
        persistence,
        anchor_failpoint,
        target,
        observed_repair,
    })
}

fn checkpoint(reopened: &mut Reopened) {
    let catalog = standard_catalog();
    let needs_provider = reopened
        .engine
        .provider_generation_projection(provider())
        .is_none();
    if needs_provider {
        reopened
            .engine
            .transact_durable(
                Command::CheckpointRecovery {
                    boot: reopened.target.boot(),
                    journal: reopened.target.journal(),
                    device: reopened.target.device(),
                },
                &mut reopened.persistence,
            )
            .unwrap();
        reopened
            .engine
            .transact_durable(
                register_provider_command(&catalog),
                &mut reopened.persistence,
            )
            .unwrap();
        return;
    }
    reopened
        .engine
        .transact_durable(
            Command::CheckpointRecovery {
                boot: reopened.target.boot(),
                journal: reopened.target.journal(),
                device: reopened.target.device(),
            },
            &mut reopened.persistence,
        )
        .unwrap();
}

fn transact(reopened: &mut Reopened, command: Command) {
    reopened
        .engine
        .transact_durable(command, &mut reopened.persistence)
        .unwrap();
}

fn create_dma_command(operation_value: u64) -> Command {
    Command::AdmitScopedCompositeEffect {
        effect: effect(operation_value, 1),
        origin: executor(operation_value, 1),
        kind: DMA_ARENA_REUSE_COMPOSITE,
        charge_account: charge(operation_value),
        bindings: vec![ComponentProviderBinding::new(
            AGENT_COMPONENT_DMA,
            provider(),
        )],
    }
}

fn add_dma_claim(operation_value: u64) -> Command {
    Command::AddComponentClaim {
        effect: effect(operation_value, 1),
        component: AGENT_COMPONENT_DMA,
        actor: executor(operation_value, 1),
        claim: claim(operation_value),
        kind: DEVICE_CLAIM_IOVA,
        scope: ClaimScope::Device(cser_core::DeviceScopeId::new(operation_value).unwrap()),
        resource: resource(operation_value),
        resource_generation: resource_generation(1),
        units: 1,
    }
}

fn bootstrap_dma(directory: &Path) {
    let mut reopened = cold_reopen(directory, 2).unwrap();
    checkpoint(&mut reopened);
    transact(&mut reopened, create_dma_command(90));
    transact(&mut reopened, add_dma_claim(90));
    transact(
        &mut reopened,
        Command::PrepareCompositeEffect {
            effect: effect(90, 1),
            actor: executor(90, 1),
        },
    );
    let intent = match reopened
        .engine
        .transact_durable(
            Command::RecordComponentCommitIntent {
                effect: effect(90, 1),
                component: AGENT_COMPONENT_DMA,
                actor: executor(90, 1),
                operation: digest(90),
            },
            &mut reopened.persistence,
        )
        .unwrap()
        .into_output()
    {
        cser_core::TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    let outcome = support::verified_commit_outcome_for_engine(
        &reopened.engine,
        &intent,
        DEVICE_VERIFIER,
        cser_core::DEVICE_COMMIT_RECEIPT_SCHEMA,
        cser_core::ExternalOutcome::Success,
        digest(91),
    );
    reopened
        .engine
        .transact_durable(
            intent.acknowledge(outcome).unwrap(),
            &mut reopened.persistence,
        )
        .unwrap();
    transact(
        &mut reopened,
        Command::FenceExecutor {
            operation: effect(90, 1).operation(),
            crashed: executor(90, 1),
        },
    );
}

#[test]
fn subprocess_persistence_entry() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    let directory = PathBuf::from(std::env::var_os(CHILD_DIRECTORY).unwrap());
    match mode.as_str() {
        "bootstrap-dma" => bootstrap_dma(&directory),
        "reserve-only" => {
            let mut anchor = open_anchor(&directory.join("anchor.bin"));
            anchor
                .reserve_recovery_epoch(binding(), DeviceGeneration::new(4).unwrap())
                .unwrap();
        }
        other => panic!("unknown child mode {other}"),
    }
}

fn run_child(mode: &str, directory: &Path) {
    let status = ProcessCommand::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("subprocess_persistence_entry")
        .arg("--nocapture")
        .env(CHILD_MODE, mode)
        .env(CHILD_DIRECTORY, directory)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn device_tombstone_and_quarantine_survive_process_and_cold_reopen() {
    let store = TempStore::new("multiprocess-device");
    run_child("bootstrap-dma", &store.directory);

    let mut reopened = cold_reopen(&store.directory, 3).unwrap();
    assert!(reopened.engine.pressure().quarantined);
    assert_eq!(reopened.engine.pressure().retained_claims, 1);
    checkpoint(&mut reopened);

    let challenge = reopened
        .engine
        .component_evidence_challenge(
            effect(90, 1),
            AGENT_COMPONENT_DMA,
            claim(90),
            DEVICE_EVIDENCE_RESET,
        )
        .unwrap();
    let wrong_subject = TestReceipt {
        effect: effect(90, 1),
        claim: claim(90),
        kind: DEVICE_EVIDENCE_RESET,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: reopened.engine.freshness(),
        subject_binding: challenge.subject_binding(),
        observation: challenge.current_observation(),
        observation_binding: challenge.current_binding(),
        digest: digest(90),
    };
    assert_eq!(
        reopened.engine.verify_component_retirement_evidence(
            effect(90, 1),
            AGENT_COMPONENT_DMA,
            claim(90),
            DEVICE_EVIDENCE_RESET,
            &ExactTestVerifier::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
            &wrong_subject,
        ),
        Err(CoreError::VerificationFailed)
    );

    let reset = TestReceipt {
        effect: effect(90, 1),
        claim: claim(90),
        kind: DEVICE_EVIDENCE_RESET,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: challenge.subject(),
        subject_binding: challenge.subject_binding(),
        observation: Freshness::new(
            challenge.current_observation().boot(),
            challenge.current_observation().registry(),
            DeviceGeneration::new(challenge.subject().device().get() + 1).unwrap(),
            challenge.current_observation().journal(),
        ),
        observation_binding: challenge.current_binding(),
        digest: digest(91),
    };
    let verified = reopened
        .engine
        .verify_component_retirement_evidence(
            effect(90, 1),
            AGENT_COMPONENT_DMA,
            claim(90),
            DEVICE_EVIDENCE_RESET,
            &ExactTestVerifier::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
            &reset,
        )
        .unwrap();
    reopened
        .engine
        .transact_durable(verified.submit(), &mut reopened.persistence)
        .unwrap();

    let challenge = reopened
        .engine
        .component_evidence_challenge(
            effect(90, 1),
            AGENT_COMPONENT_DMA,
            claim(90),
            DEVICE_EVIDENCE_IOTLB,
        )
        .unwrap();
    let iotlb = TestReceipt {
        effect: effect(90, 1),
        claim: claim(90),
        kind: DEVICE_EVIDENCE_IOTLB,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: challenge.subject(),
        subject_binding: challenge.subject_binding(),
        observation: challenge.current_observation(),
        observation_binding: challenge.current_binding(),
        digest: digest(92),
    };
    let verified = reopened
        .engine
        .verify_component_retirement_evidence(
            effect(90, 1),
            AGENT_COMPONENT_DMA,
            claim(90),
            DEVICE_EVIDENCE_IOTLB,
            &ExactTestVerifier::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
            &iotlb,
        )
        .unwrap();
    reopened
        .engine
        .transact_durable(verified.submit(), &mut reopened.persistence)
        .unwrap();
    assert_eq!(reopened.engine.pressure().retained_claims, 0);
    drop(reopened);

    run_child("reserve-only", &store.directory);
    let mut final_reopen = cold_reopen(&store.directory, 4).unwrap();
    assert_eq!(final_reopen.target.boot().get(), 5);
    assert_eq!(final_reopen.target.journal().get(), 5);
    assert!(!final_reopen.engine.pressure().quarantined);
    assert_eq!(final_reopen.engine.pressure().retained_claims, 0);
    checkpoint(&mut final_reopen);
}

#[test]
fn crash_windows_reconcile_to_the_exact_trusted_prefix() {
    let torn = TempStore::new("torn");
    let mut opened = cold_reopen(&torn.directory, 1).unwrap();
    checkpoint(&mut opened);
    let journal_path = torn.journal();
    let result = opened.engine.transact(create_dma_command(101), |record| {
        let mut file = OpenOptions::new().append(true).open(&journal_path).unwrap();
        file.write_all(&record.bytes()[..record.bytes().len() / 2])
            .unwrap();
        file.sync_all().unwrap();
        Err::<(), _>("injected torn write")
    });
    assert!(matches!(result, Err(TxError::Persist(_))));
    drop(opened);
    let repaired = cold_reopen(&torn.directory, 1).unwrap();
    // The streaming anchored reader classifies all unread residue uniformly;
    // repair still truncates to the exact trusted prefix.
    assert!(matches!(
        repaired.observed_repair,
        Some(JournalRepair::UnanchoredSuffix { .. })
    ));
    assert!(repaired.engine.composite_effect(effect(101, 1)).is_none());

    let suffix = TempStore::new("unanchored-suffix");
    let mut opened = cold_reopen(&suffix.directory, 1).unwrap();
    checkpoint(&mut opened);
    opened
        .anchor_failpoint
        .arm(HostAnchorFailpoint::BeforeAtomicReplace);
    let result = opened
        .engine
        .transact_durable(create_dma_command(102), &mut opened.persistence);
    assert!(matches!(result, Err(TxError::Persist(_))));
    assert!(opened.persistence.recovery_required());
    drop(opened);
    let repaired = cold_reopen(&suffix.directory, 1).unwrap();
    assert!(matches!(
        repaired.observed_repair,
        Some(JournalRepair::UnanchoredSuffix { .. })
    ));
    assert!(repaired.engine.composite_effect(effect(102, 1)).is_none());

    let lost_ack = TempStore::new("anchor-ack-lost");
    let mut opened = cold_reopen(&lost_ack.directory, 1).unwrap();
    checkpoint(&mut opened);
    opened
        .anchor_failpoint
        .arm(HostAnchorFailpoint::AfterAtomicReplaceBeforeReturn);
    let result = opened
        .engine
        .transact_durable(create_dma_command(103), &mut opened.persistence);
    assert!(matches!(result, Err(TxError::Persist(_))));
    drop(opened);
    let replayed = cold_reopen(&lost_ack.directory, 1).unwrap();
    assert_eq!(replayed.observed_repair, None);
    assert!(replayed.engine.composite_effect(effect(103, 1)).is_some());
}

#[test]
fn binding_device_and_journal_rollback_fail_closed() {
    let store = TempStore::new("negative");
    let mut anchor = open_anchor(&store.anchor());
    anchor
        .reserve_recovery_epoch(binding(), DeviceGeneration::new(2).unwrap())
        .unwrap();
    assert!(
        anchor
            .reserve_recovery_epoch(binding(), DeviceGeneration::new(1).unwrap())
            .is_err()
    );
    // The former global authority-generation coordinate is no longer part of
    // the binding. Equal typed coordinates therefore replay identically.
    let formerly_different_binding = RecoveryBinding::new(
        RecoveryProfile::current(),
        WorldId::new(1).unwrap(),
        CatalogSet::new(&[standard_catalog()]).unwrap().digest(),
        freshness(1, 1, 1, 1).registry(),
    )
    .unwrap();
    assert_eq!(formerly_different_binding, binding());
    anchor
        .reserve_recovery_epoch(
            formerly_different_binding,
            DeviceGeneration::new(2).unwrap(),
        )
        .unwrap();
    let wrong_catalog = RecoveryBinding::new(
        RecoveryProfile::current(),
        WorldId::new(1).unwrap(),
        digest(201),
        freshness(1, 1, 1, 1).registry(),
    )
    .unwrap();
    assert!(
        anchor
            .reserve_recovery_epoch(wrong_catalog, DeviceGeneration::new(3).unwrap())
            .is_err()
    );
    let snapshot = TrustedAnchorSnapshot::from_trusted_backend(
        binding(),
        freshness(1, 1, 1, 1),
        0,
        cser_core::Digest::ZERO,
        genesis_projection(),
    )
    .unwrap();
    assert!(RecoveryLease::from_trusted_backend(snapshot, freshness(1, 1, 1, 1)).is_err());
}

#[test]
fn file_journal_trait_is_an_exact_append_and_sync_adapter() {
    fn assert_backend<T: DurableJournalBackend<Error = std::io::Error>>() {}
    assert_backend::<FileJournal>();
    let _ = cser_core::ReceiptBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA);
    let _ = cser_core::TransitionOutput::None;
}
