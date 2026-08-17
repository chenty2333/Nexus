use cser_core::{
    BootGeneration, CatalogSet, ChargeAccountId, ClaimId, Command as AuthorizedCommand,
    CommandRequest as Command, ComponentId, ComponentProviderBinding, CoreError, CoreLimits,
    DeviceGeneration, Digest, EffectFactKind, EffectId, EffectReceiptVerifier, Engine,
    ExecutorCoordinate, ExecutorGeneration, ExecutorId, ExternalOutcome, Freshness,
    JournalCheckpoint, JournalGeneration, OperationId, ProviderCoordinate, ProviderGeneration,
    ProviderId, ReceiptBinding, ReceiptSchemaId, ReceiptVerifier, RecoveryAnchor, RecoveryBinding,
    RecoveryProfile, RegistryInstance, ResourceGeneration, ResourceId, SnapshotId,
    TransitionOutput, TransitionReceipt, TxError, VerificationError, VerifiedApplyReceipt,
    VerifiedCommitOutcome, VerifiedEffectObservation, VerifiedObservation, VerifiedSettlementAck,
    VerifierBinding, VerifierClassBinding, VerifierGeneration, VerifierId, VerifierIdentity,
    WorldId, standard_catalog, tool_dma_catalog,
};

pub const EFFECT_CATALOG_KIND: cser_core::CompositeKindId =
    cser_core::TOOL_HANDOFF_SOURCE_COMPOSITE;
pub const EFFECT_COMPONENT: ComponentId = cser_core::TOOL_HANDOFF_SOURCE_COMPONENT;
pub const EFFECT_DOMAIN: cser_core::DomainId = cser_core::TOOL_DOMAIN;
pub const EFFECT_OBLIGATION: cser_core::ObligationKindId = cser_core::TOOL_OBLIGATION_INVOCATION;
pub const EFFECT_CLAIM_KIND: cser_core::ClaimKindId = cser_core::TOOL_CLAIM_OUTCOME_SLOT;
pub const EFFECT_EVIDENCE_KIND: cser_core::EvidenceKindId = cser_core::TOOL_EVIDENCE_OUTCOME_ACK;
pub const EFFECT_VERIFIER: VerifierId = cser_core::TOOL_VERIFIER;
pub const EFFECT_RECEIPT_SCHEMA: ReceiptSchemaId = cser_core::TOOL_RECEIPT_SCHEMA;
pub const EFFECT_COMMIT_RECEIPT_SCHEMA: ReceiptSchemaId = cser_core::TOOL_COMMIT_RECEIPT_SCHEMA;
pub const EFFECT_APPLY_RECEIPT_SCHEMA: ReceiptSchemaId = cser_core::TOOL_APPLY_RECEIPT_SCHEMA;
pub const EFFECT_SETTLEMENT_RECEIPT_SCHEMA: ReceiptSchemaId =
    cser_core::TOOL_SETTLEMENT_RECEIPT_SCHEMA;
pub const EFFECT_CREDIT: cser_core::CreditClassId = cser_core::CREDIT_TOOL_OUTCOME_SLOT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestReceipt {
    pub effect: EffectId,
    pub claim: ClaimId,
    pub kind: cser_core::EvidenceKindId,
    pub resource: ResourceId,
    pub resource_generation: ResourceGeneration,
    pub subject: Freshness,
    pub observation: Freshness,
    pub digest: Digest,
}

#[derive(Clone, Copy, Debug)]
pub struct ExactTestVerifier {
    identity: VerifierIdentity,
}

impl ExactTestVerifier {
    pub fn new(verifier: VerifierId, receipt_schema: ReceiptSchemaId) -> Self {
        let binding = verifier_binding(verifier, receipt_schema);
        Self {
            identity: VerifierIdentity::new_exact(binding),
        }
    }
}

impl ReceiptVerifier for ExactTestVerifier {
    type Receipt = TestReceipt;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestEffectReceipt {
    pub kind: EffectFactKind,
    pub effect: EffectId,
    pub domain: cser_core::DomainId,
    pub obligation: cser_core::ObligationKindId,
    pub actor: ExecutorCoordinate,
    pub generation: u64,
    pub nonce: u64,
    pub operation: Digest,
    pub predecessor: Option<Digest>,
    pub freshness: Freshness,
    pub digest: Digest,
    pub outcome: Option<ExternalOutcome>,
}

#[derive(Clone, Copy, Debug)]
pub struct ExactEffectVerifier {
    identity: VerifierIdentity,
}

impl ExactEffectVerifier {
    pub fn new(verifier: VerifierId, receipt_schema: ReceiptSchemaId) -> Self {
        let binding = verifier_binding(verifier, receipt_schema);
        Self {
            identity: VerifierIdentity::new_exact(binding),
        }
    }
}

impl EffectReceiptVerifier for ExactEffectVerifier {
    type Receipt = TestEffectReceipt;

    fn identity(&self) -> VerifierIdentity {
        self.identity
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

pub struct Harness {
    pub engine: Engine,
    pub journal: Vec<u8>,
}

impl Harness {
    pub fn new() -> Self {
        Self::with_catalog(tool_dma_catalog(), CoreLimits::bounded_default())
    }

    pub fn with_limits(limits: CoreLimits) -> Self {
        Self::with_catalog(tool_dma_catalog(), limits)
    }

    pub fn standard() -> Self {
        Self::with_catalog(standard_catalog(), CoreLimits::bounded_default())
    }

    pub fn with_catalog(catalog: cser_core::DomainCatalog, limits: CoreLimits) -> Self {
        let catalog_set = CatalogSet::new(core::slice::from_ref(&catalog)).unwrap();
        let mut harness = Self {
            engine: Engine::new(test_world(), catalog_set, limits, freshness(1, 1, 1, 1)),
            journal: Vec::new(),
        };
        harness.tx(register_provider_command(&catalog)).unwrap();
        harness
    }

    pub fn tx<C>(&mut self, command: C) -> Result<TransitionReceipt, CoreError>
    where
        C: Into<AuthorizedCommand>,
    {
        let journal = &mut self.journal;
        let command: AuthorizedCommand = command.into();
        self.engine
            .transact(command, |record| {
                journal.extend_from_slice(record.bytes());
                Ok::<(), ()>(())
            })
            .map_err(|error| match error {
                TxError::Core(error) => error,
                TxError::Journal(error) => CoreError::Journal(error),
                TxError::Persist(()) => unreachable!("memory persistence cannot fail"),
            })
    }

    pub fn output<C>(&mut self, command: C) -> TransitionOutput
    where
        C: Into<AuthorizedCommand>,
    {
        self.tx(command).unwrap().into_output()
    }

    /// Captures the in-memory durable journal as a validated exact-replay image.
    ///
    /// Test persistence deliberately uses the same checkpoint construction as
    /// a replacement backend rather than treating a copied `Vec<u8>` as an
    /// independently authoritative state source.
    pub fn checkpoint(&self) -> JournalCheckpoint {
        self.engine.journal_checkpoint(&self.journal).unwrap()
    }
}

pub fn test_world() -> WorldId {
    WorldId::new(1).unwrap()
}

pub fn recovery_binding(catalog_digest: Digest, freshness: Freshness) -> RecoveryBinding {
    RecoveryBinding::new(
        RecoveryProfile::current(),
        test_world(),
        catalog_digest,
        freshness.registry(),
    )
    .unwrap()
}

pub fn provider() -> ProviderCoordinate {
    ProviderCoordinate::new(
        test_world(),
        ProviderId::new(1).unwrap(),
        ProviderGeneration::new(1).unwrap(),
    )
}

pub fn verifier_binding(verifier: VerifierId, receipt_schema: ReceiptSchemaId) -> VerifierBinding {
    VerifierBinding::new(
        verifier,
        VerifierGeneration::new(1).unwrap(),
        receipt_schema,
        digest((verifier.get() as u8).wrapping_add(receipt_schema.get() as u8)),
    )
    .unwrap()
}

pub fn register_provider_command(catalog: &cser_core::DomainCatalog) -> Command {
    Command::RegisterProviderGeneration {
        coordinate: provider(),
        catalog_digest: catalog.digest(),
        verifier_bindings: catalog
            .verifier_class_bindings()
            .into_iter()
            .map(|class: VerifierClassBinding| {
                verifier_binding(class.verifier(), class.receipt_schema())
            })
            .collect(),
    }
}

pub fn admit_command(effect: EffectId, operation_value: u64) -> Command {
    Command::AdmitScopedCompositeEffect {
        effect,
        origin: executor(operation_value, 1),
        kind: EFFECT_CATALOG_KIND,
        charge_account: charge(operation_value),
        bindings: vec![ComponentProviderBinding::new(EFFECT_COMPONENT, provider())],
    }
}

pub fn genesis_projection() -> Digest {
    Engine::new(
        test_world(),
        CatalogSet::new(&[standard_catalog()]).unwrap(),
        CoreLimits::bounded_default(),
        freshness(1, 1, 1, 1),
    )
    .projection_digest()
}

pub fn recovery_anchor(
    catalog_digest: Digest,
    committed: Freshness,
    next: Freshness,
    minimum_revision: u64,
    expected_head: Digest,
    projection: Digest,
) -> RecoveryAnchor {
    RecoveryAnchor::from_trusted_provider(
        recovery_binding(catalog_digest, committed),
        committed,
        next,
        minimum_revision,
        expected_head,
        projection,
    )
    .unwrap()
}

pub fn effect(operation_value: u64, sequence: u64) -> EffectId {
    EffectId::new(OperationId::new(operation_value).unwrap(), sequence).unwrap()
}

pub fn executor(id: u64, generation: u64) -> ExecutorCoordinate {
    ExecutorCoordinate::new(
        ExecutorId::new(id).unwrap(),
        ExecutorGeneration::new(generation).unwrap(),
    )
}

pub fn charge(value: u64) -> ChargeAccountId {
    ChargeAccountId::new(value).unwrap()
}

pub fn claim(value: u64) -> ClaimId {
    ClaimId::new(value).unwrap()
}

pub fn resource(value: u64) -> ResourceId {
    ResourceId::new(value).unwrap()
}

pub fn resource_generation(value: u64) -> ResourceGeneration {
    ResourceGeneration::new(value).unwrap()
}

pub fn snapshot(value: u64) -> SnapshotId {
    SnapshotId::new(value).unwrap()
}

pub fn digest(value: u8) -> Digest {
    let mut bytes = [0u8; 32];
    bytes[0] = value;
    Digest::new(bytes)
}

pub fn verified_evidence_command(
    harness: &Harness,
    effect: EffectId,
    claim: ClaimId,
    kind: cser_core::EvidenceKindId,
    receipt_binding: ReceiptBinding,
    observation: Freshness,
    receipt_digest: Digest,
) -> AuthorizedCommand {
    let challenge = harness
        .engine
        .component_evidence_challenge(effect, EFFECT_COMPONENT, claim, kind)
        .unwrap();
    let verifier =
        ExactTestVerifier::new(receipt_binding.verifier(), receipt_binding.receipt_schema());
    let receipt = TestReceipt {
        effect,
        claim,
        kind,
        resource: challenge.resource(),
        resource_generation: challenge.resource_generation(),
        subject: challenge.subject(),
        observation,
        digest: receipt_digest,
    };
    harness
        .engine
        .verify_component_retirement_evidence(
            effect,
            EFFECT_COMPONENT,
            claim,
            kind,
            &verifier,
            &receipt,
        )
        .unwrap()
        .submit()
}

pub fn current_evidence_command(
    harness: &Harness,
    effect: EffectId,
    claim: ClaimId,
    kind: cser_core::EvidenceKindId,
    receipt_binding: ReceiptBinding,
    receipt_digest: Digest,
) -> AuthorizedCommand {
    let observation = harness
        .engine
        .component_evidence_challenge(effect, EFFECT_COMPONENT, claim, kind)
        .unwrap()
        .current_observation();
    verified_evidence_command(
        harness,
        effect,
        claim,
        kind,
        receipt_binding,
        observation,
        receipt_digest,
    )
}

pub fn snapshot_command(
    harness: &Harness,
    operation: OperationId,
    snapshot: SnapshotId,
) -> AuthorizedCommand {
    harness
        .engine
        .snapshot_operation(operation, snapshot)
        .unwrap()
        .record()
}

pub fn test_effect_receipt(
    challenge: cser_core::EffectFactChallenge,
    digest: Digest,
    outcome: Option<ExternalOutcome>,
) -> TestEffectReceipt {
    TestEffectReceipt {
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

pub fn verified_commit_outcome(
    harness: &Harness,
    intent: &cser_core::CommitIntent,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
    outcome: ExternalOutcome,
    digest: Digest,
) -> VerifiedCommitOutcome {
    verified_commit_outcome_for_engine(
        &harness.engine,
        intent,
        verifier,
        receipt_schema,
        outcome,
        digest,
    )
}

pub fn verified_commit_outcome_for_engine(
    engine: &Engine,
    intent: &cser_core::CommitIntent,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
    outcome: ExternalOutcome,
    digest: Digest,
) -> VerifiedCommitOutcome {
    let challenge = engine.commit_outcome_challenge(intent).unwrap();
    let receipt = test_effect_receipt(challenge, digest, Some(outcome));
    engine
        .verify_commit_outcome(
            intent,
            &ExactEffectVerifier::new(verifier, receipt_schema),
            &receipt,
        )
        .unwrap()
}

pub fn verified_apply_completion(
    harness: &Harness,
    claim: &cser_core::SettlementClaim,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
    digest: Digest,
) -> VerifiedApplyReceipt {
    verified_apply_completion_for_engine(&harness.engine, claim, verifier, receipt_schema, digest)
}

pub fn verified_apply_completion_for_engine(
    engine: &Engine,
    claim: &cser_core::SettlementClaim,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
    digest: Digest,
) -> VerifiedApplyReceipt {
    let challenge = engine.apply_completion_challenge(claim).unwrap();
    let receipt = test_effect_receipt(challenge, digest, None);
    engine
        .verify_apply_completion(
            claim,
            &ExactEffectVerifier::new(verifier, receipt_schema),
            &receipt,
        )
        .unwrap()
}

pub fn verified_settlement_ack(
    harness: &Harness,
    claim: &cser_core::SettlementClaim,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
    digest: Digest,
) -> VerifiedSettlementAck {
    verified_settlement_ack_for_engine(&harness.engine, claim, verifier, receipt_schema, digest)
}

pub fn verified_settlement_ack_for_engine(
    engine: &Engine,
    claim: &cser_core::SettlementClaim,
    verifier: VerifierId,
    receipt_schema: ReceiptSchemaId,
    digest: Digest,
) -> VerifiedSettlementAck {
    let challenge = engine.settlement_ack_challenge(claim).unwrap();
    let receipt = test_effect_receipt(challenge, digest, None);
    engine
        .verify_settlement_ack(
            claim,
            &ExactEffectVerifier::new(verifier, receipt_schema),
            &receipt,
        )
        .unwrap()
}

pub fn freshness(boot: u64, registry: u64, device: u64, journal: u64) -> Freshness {
    Freshness::new(
        BootGeneration::new(boot).unwrap(),
        RegistryInstance::new(registry).unwrap(),
        DeviceGeneration::new(device).unwrap(),
        JournalGeneration::new(journal).unwrap(),
    )
}

pub fn committed_reply(
    harness: &mut Harness,
    operation_value: u64,
) -> (EffectId, ExecutorCoordinate) {
    let (effect, origin) = prepared_reply(harness, operation_value);
    let intent = match harness.output(Command::RecordComponentCommitIntent {
        effect,
        component: EFFECT_COMPONENT,
        actor: origin,
        operation: digest(10),
    }) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    let outcome = verified_commit_outcome(
        harness,
        &intent,
        EFFECT_VERIFIER,
        EFFECT_COMMIT_RECEIPT_SCHEMA,
        ExternalOutcome::Success,
        digest(11),
    );
    harness.tx(intent.acknowledge(outcome).unwrap()).unwrap();
    (effect, origin)
}

pub fn prepared_reply(
    harness: &mut Harness,
    operation_value: u64,
) -> (EffectId, ExecutorCoordinate) {
    let effect = effect(operation_value, 1);
    let origin = executor(operation_value, 1);
    harness.tx(admit_command(effect, operation_value)).unwrap();
    harness
        .tx(Command::AddComponentClaim {
            effect,
            component: EFFECT_COMPONENT,
            actor: origin,
            claim: claim(operation_value),
            kind: EFFECT_CLAIM_KIND,
            scope: cser_core::ClaimScope::Logical,
            resource: resource(operation_value),
            resource_generation: resource_generation(1),
            units: 1,
        })
        .unwrap();
    harness
        .tx(Command::PrepareCompositeEffect {
            effect,
            actor: origin,
        })
        .unwrap();
    (effect, origin)
}

pub fn fence_and_rebind(
    harness: &mut Harness,
    effect: EffectId,
    crashed: ExecutorCoordinate,
    successor: ExecutorCoordinate,
    snapshot_value: u64,
) {
    harness
        .tx(Command::FenceExecutor {
            operation: effect.operation(),
            crashed,
        })
        .unwrap();
    let snapshot = snapshot(snapshot_value);
    let snapshot_record = snapshot_command(harness, effect.operation(), snapshot);
    harness.tx(snapshot_record).unwrap();
    harness
        .tx(Command::Ready {
            operation: effect.operation(),
            snapshot,
            successor,
        })
        .unwrap();
    harness
        .tx(Command::Rebind {
            operation: effect.operation(),
            snapshot,
            successor,
        })
        .unwrap();
}
