use cser_core::{
    AdoptionPolicy, ArtifactAdmission, ArtifactLeaseState as CoreArtifactLeaseState,
    ArtifactPinChallenge, ArtifactPinVerifier, ArtifactReceiptBindings, ArtifactReleaseChallenge,
    ArtifactReleaseVerifier, BootGeneration, CatalogSet, ClaimCardinality, ClaimId, ClaimKindId,
    ClaimScope, CommandRequest, CommitState, ComponentId, ComponentProviderBinding,
    CompositeComponentSpec, CompositeKindId, CoreError, CoreLimits, CreditClassId, CustodyState,
    DeviceGeneration, DeviceGenerationEffect, Digest, DomainCatalog, DomainCatalogBuilder,
    DomainId, EffectFactChallenge, EffectId, EffectReceiptVerifier, Engine, EvidenceKindId,
    EvidenceRule, ExecutorCoordinate, ExecutorGeneration, ExecutorId, ExternalOutcome, Freshness,
    FreshnessAxes, JournalGeneration, ObligationKindId, ObligationPolicy, ObligationReceipts,
    ObligationSpec, OperationId, OutcomeState, ProviderCoordinate, ProviderEffectState,
    ProviderGeneration, ProviderId, ReceiptBinding, ReceiptSchemaId, ReceiptVerifier,
    RecoveryAnchor, RecoveryArtifactId, RecoveryArtifactPolicy, RecoveryBinding, RecoveryProfile,
    RegistryInstance, ResourceGeneration, ResourceId, RetirementState, SettlementState,
    TransitionEvent, TransitionOutput, VerificationError, VerifiedEffectObservation,
    VerifiedObservation, VerifierBinding, VerifierGeneration, VerifierIdentity, WorldId,
};

use cser_model::recovery_artifact_oracle::{
    ArtifactLeaseState as OracleArtifactLeaseState, ArtifactOwner,
    ComponentPhase as OracleComponentPhase, ProviderPhase as OracleProviderPhase,
    RecoveryArtifactOracle,
};
use cser_model::{
    ArtifactId as OracleArtifactId, ComponentId as OracleComponentId, EffectId as OracleEffectId,
    OperationId as OracleOperationId, ProviderGeneration as OracleProviderGeneration,
    ProviderId as OracleProviderId, WorldId as OracleWorldId,
};

const WORLD: u64 = 7_001;
const PROVIDER: u64 = 7_002;
const DOMAIN: u64 = 7_003;
const OBLIGATION: u64 = 7_004;
const CLAIM: u64 = 7_005;
const COMPONENT: u64 = 7_006;
const COMPOSITE: u64 = 7_007;
const CREDIT: u64 = 7_008;
const COMMIT_VERIFIER: u64 = 7_009;
const COMMIT_SCHEMA: u64 = 7_010;
const EVIDENCE_VERIFIER: u64 = 7_011;
const EVIDENCE_SCHEMA: u64 = 7_012;
const ARTIFACT_PIN_VERIFIER: u64 = 7_013;
const ARTIFACT_PIN_SCHEMA: u64 = 7_014;
const ARTIFACT_RELEASE_VERIFIER: u64 = 7_015;
const ARTIFACT_RELEASE_SCHEMA: u64 = 7_016;
const COMPONENT_TWO: u64 = 7_018;

fn freshness() -> Freshness {
    Freshness::new(
        BootGeneration::new(1).unwrap(),
        RegistryInstance::new(1).unwrap(),
        DeviceGeneration::new(1).unwrap(),
        JournalGeneration::new(1).unwrap(),
    )
}

fn id<T>(value: u64, make: impl FnOnce(u32) -> Result<T, cser_core::IdentityError>) -> T {
    make(value as u32).unwrap()
}

fn catalog() -> DomainCatalog {
    let domain = id(DOMAIN, DomainId::new);
    let obligation = id(OBLIGATION, ObligationKindId::new);
    let claim = id(CLAIM, ClaimKindId::new);
    let component = id(COMPONENT, ComponentId::new);
    let credit = id(CREDIT, CreditClassId::new);
    let commit = ReceiptBinding::new(
        id(COMMIT_VERIFIER, cser_core::VerifierId::new),
        id(COMMIT_SCHEMA, ReceiptSchemaId::new),
    );
    let evidence = ReceiptBinding::new(
        id(EVIDENCE_VERIFIER, cser_core::VerifierId::new),
        id(EVIDENCE_SCHEMA, ReceiptSchemaId::new),
    );
    let freshness_axes = FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::JOURNAL);

    DomainCatalogBuilder::new()
        .credit_class(credit, 4)
        .unwrap()
        .obligation(
            ObligationSpec::new(
                domain,
                obligation,
                ObligationPolicy::SuccessorSettlement,
                AdoptionPolicy::UncommittedOnly,
                ObligationReceipts::successor_settlement(commit, commit, commit),
                1,
            ),
            &[ClaimCardinality::new(claim, 1, 1).unwrap()],
        )
        .unwrap()
        .claim(
            domain,
            claim,
            credit,
            cser_core::ClaimScopePolicy::Logical,
            &[EvidenceRule::retirement(
                id(EVIDENCE_KIND, EvidenceKindId::new),
                evidence,
                freshness_axes,
                freshness_axes,
                FreshnessAxes::BOOT,
                DeviceGenerationEffect::None,
                None,
            )],
        )
        .unwrap()
        .composite(
            id(COMPOSITE, CompositeKindId::new),
            &[CompositeComponentSpec::new_with_artifact_policy(
                component,
                domain,
                obligation,
                RecoveryArtifactPolicy::Required,
            )],
        )
        .unwrap()
        .build()
        .unwrap()
}

fn mixed_catalog() -> DomainCatalog {
    let domain = id(DOMAIN, DomainId::new);
    let obligation = id(OBLIGATION, ObligationKindId::new);
    let claim = id(CLAIM, ClaimKindId::new);
    let component = id(COMPONENT, ComponentId::new);
    let component_two = id(COMPONENT_TWO, ComponentId::new);
    let credit = id(CREDIT, CreditClassId::new);
    let commit = ReceiptBinding::new(
        id(COMMIT_VERIFIER, cser_core::VerifierId::new),
        id(COMMIT_SCHEMA, ReceiptSchemaId::new),
    );
    let evidence = ReceiptBinding::new(
        id(EVIDENCE_VERIFIER, cser_core::VerifierId::new),
        id(EVIDENCE_SCHEMA, ReceiptSchemaId::new),
    );
    let freshness_axes = FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::JOURNAL);

    DomainCatalogBuilder::new()
        .credit_class(credit, 4)
        .unwrap()
        .obligation(
            ObligationSpec::new(
                domain,
                obligation,
                ObligationPolicy::SuccessorSettlement,
                AdoptionPolicy::UncommittedOnly,
                ObligationReceipts::successor_settlement(commit, commit, commit),
                1,
            ),
            &[ClaimCardinality::new(claim, 1, 1).unwrap()],
        )
        .unwrap()
        .claim(
            domain,
            claim,
            credit,
            cser_core::ClaimScopePolicy::Logical,
            &[EvidenceRule::retirement(
                id(EVIDENCE_KIND, EvidenceKindId::new),
                evidence,
                freshness_axes,
                freshness_axes,
                FreshnessAxes::BOOT,
                DeviceGenerationEffect::None,
                None,
            )],
        )
        .unwrap()
        .composite(
            id(COMPOSITE, CompositeKindId::new),
            &[
                CompositeComponentSpec::new_with_artifact_policy(
                    component,
                    domain,
                    obligation,
                    RecoveryArtifactPolicy::Required,
                ),
                CompositeComponentSpec::new_with_artifact_policy(
                    component_two,
                    domain,
                    obligation,
                    RecoveryArtifactPolicy::Required,
                ),
            ],
        )
        .unwrap()
        .build()
        .unwrap()
}

const EVIDENCE_KIND: u64 = 7_017;

fn provider(world: WorldId) -> ProviderCoordinate {
    ProviderCoordinate::new(
        world,
        ProviderId::new(PROVIDER).unwrap(),
        ProviderGeneration::new(1).unwrap(),
    )
}

fn artifact_receipts() -> ArtifactReceiptBindings {
    ArtifactReceiptBindings::new(
        VerifierBinding::new(
            id(ARTIFACT_PIN_VERIFIER, cser_core::VerifierId::new),
            VerifierGeneration::new(1).unwrap(),
            id(ARTIFACT_PIN_SCHEMA, ReceiptSchemaId::new),
            Digest::new([0xa1; 32]),
        )
        .unwrap(),
        VerifierBinding::new(
            id(ARTIFACT_RELEASE_VERIFIER, cser_core::VerifierId::new),
            VerifierGeneration::new(1).unwrap(),
            id(ARTIFACT_RELEASE_SCHEMA, ReceiptSchemaId::new),
            Digest::new([0xa2; 32]),
        )
        .unwrap(),
    )
}

fn provider_verifiers(catalog: &DomainCatalog) -> Vec<VerifierBinding> {
    catalog
        .verifier_class_bindings()
        .into_iter()
        .enumerate()
        .map(|(index, class)| {
            VerifierBinding::new(
                class.verifier(),
                VerifierGeneration::new(1).unwrap(),
                class.receipt_schema(),
                Digest::new([0x20 + index as u8; 32]),
            )
            .unwrap()
        })
        .collect()
}

fn registered_engine_with_catalog(
    catalog: DomainCatalog,
) -> (Engine, DomainCatalog, ProviderCoordinate) {
    let world = WorldId::new(WORLD).unwrap();
    let provider = provider(world);
    let mut engine = Engine::new(
        world,
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    engine
        .transact_volatile(CommandRequest::RegisterProviderGeneration {
            coordinate: provider,
            catalog_digest: catalog.digest(),
            verifier_bindings: provider_verifiers(&catalog),
        })
        .unwrap();
    engine
        .transact_volatile(CommandRequest::BindArtifactReceiptVerifiers {
            coordinate: provider,
            receipts: artifact_receipts(),
        })
        .unwrap();
    (engine, catalog, provider)
}

fn registered_engine() -> (Engine, DomainCatalog, ProviderCoordinate) {
    registered_engine_with_catalog(catalog())
}

fn fixture(
    effect_value: u64,
) -> (
    Engine,
    DomainCatalog,
    ProviderCoordinate,
    EffectId,
    ExecutorCoordinate,
) {
    let (mut engine, catalog, provider) = registered_engine();
    let effect = EffectId::new(OperationId::new(effect_value).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(effect_value).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    let admission = ArtifactAdmission::new(
        RecoveryArtifactId::new(effect_value + 2).unwrap(),
        Digest::new([0x51; 32]),
        Digest::new([0x52; 32]),
    );
    engine
        .transact_volatile(CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin: actor,
            kind: id(COMPOSITE, CompositeKindId::new),
            charge_account: cser_core::ChargeAccountId::new(effect_value).unwrap(),
            bindings: vec![
                ComponentProviderBinding::new(id(COMPONENT, ComponentId::new), provider)
                    .with_artifact(admission),
            ],
        })
        .unwrap();
    (engine, catalog, provider, effect, actor)
}

fn mixed_fixture(effect_value: u64) -> (Engine, DomainCatalog, ProviderCoordinate, EffectId) {
    let (mut engine, catalog, provider) = registered_engine_with_catalog(mixed_catalog());
    let effect = EffectId::new(OperationId::new(effect_value).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(effect_value).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    let first = ArtifactAdmission::new(
        RecoveryArtifactId::new(effect_value + 2).unwrap(),
        Digest::new([0x51; 32]),
        Digest::new([0x52; 32]),
    );
    let second = ArtifactAdmission::new(
        RecoveryArtifactId::new(effect_value + 3).unwrap(),
        Digest::new([0x53; 32]),
        Digest::new([0x54; 32]),
    );
    engine
        .transact_volatile(CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin: actor,
            kind: id(COMPOSITE, CompositeKindId::new),
            charge_account: cser_core::ChargeAccountId::new(effect_value).unwrap(),
            bindings: vec![
                ComponentProviderBinding::new(id(COMPONENT, ComponentId::new), provider)
                    .with_artifact(first),
                ComponentProviderBinding::new(id(COMPONENT_TWO, ComponentId::new), provider)
                    .with_artifact(second),
            ],
        })
        .unwrap();
    (engine, catalog, provider, effect)
}

fn prepare(engine: &mut Engine, effect: EffectId, actor: ExecutorCoordinate, value: u64) {
    engine
        .transact_volatile(CommandRequest::AddComponentClaim {
            effect,
            component: id(COMPONENT, ComponentId::new),
            actor,
            claim: cser_core::ClaimId::new(value).unwrap(),
            kind: id(CLAIM, ClaimKindId::new),
            scope: ClaimScope::Logical,
            resource: ResourceId::new(value).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        })
        .unwrap();
    engine
        .transact_volatile(CommandRequest::PrepareCompositeEffect { effect, actor })
        .unwrap();
}

fn pin_component(engine: &mut Engine, effect: EffectId, component: ComponentId) {
    let verifier = AcceptPin(artifact_receipts().pin());
    let proof = engine
        .verify_artifact_pin(effect, component, &verifier, &())
        .unwrap();
    engine.transact_volatile(proof.record()).unwrap();
}

fn pin(engine: &mut Engine, effect: EffectId) {
    pin_component(engine, effect, id(COMPONENT, ComponentId::new));
}

struct AcceptPin(VerifierBinding);

impl ArtifactPinVerifier for AcceptPin {
    type Receipt = ();

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new_exact(self.0)
    }

    fn verify(
        &self,
        _challenge: &ArtifactPinChallenge,
        _receipt: &Self::Receipt,
    ) -> Result<Digest, VerificationError> {
        Ok(Digest::new([0x71; 32]))
    }
}

struct AcceptRelease(VerifierBinding);

impl ArtifactReleaseVerifier for AcceptRelease {
    type Receipt = ();

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new_exact(self.0)
    }

    fn verify(
        &self,
        _challenge: &ArtifactReleaseChallenge,
        _receipt: &Self::Receipt,
    ) -> Result<Digest, VerificationError> {
        Ok(Digest::new([0x72; 32]))
    }
}

#[derive(Clone, Copy)]
struct AcceptEffectFact {
    identity: VerifierIdentity,
    outcome: Option<ExternalOutcome>,
    digest: Digest,
}

impl EffectReceiptVerifier for AcceptEffectFact {
    type Receipt = ();

    fn identity(&self) -> VerifierIdentity {
        self.identity
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        _receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, VerificationError> {
        Ok(match self.outcome {
            Some(outcome) => VerifiedEffectObservation::commit(
                challenge.current_observation(),
                outcome,
                self.digest,
            ),
            None => VerifiedEffectObservation::fact(challenge.current_observation(), self.digest),
        })
    }
}

#[derive(Clone, Copy)]
struct AcceptEvidence(VerifierIdentity);

impl ReceiptVerifier for AcceptEvidence {
    type Receipt = ();

    fn identity(&self) -> VerifierIdentity {
        self.0
    }

    fn verify(
        &self,
        challenge: &cser_core::EvidenceChallenge,
        _receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        Ok(VerifiedObservation::new(
            challenge.subject(),
            challenge.current_observation(),
            Digest::new([0x79; 32]),
        ))
    }
}

fn scoped_identity(
    catalog: &DomainCatalog,
    verifier: cser_core::VerifierId,
    schema: ReceiptSchemaId,
) -> VerifierIdentity {
    let index = catalog
        .verifier_class_bindings()
        .into_iter()
        .enumerate()
        .find(|(_, binding)| binding.verifier() == verifier && binding.receipt_schema() == schema)
        .map(|(index, _)| index)
        .unwrap();
    VerifierIdentity::new_exact(
        VerifierBinding::new(
            verifier,
            VerifierGeneration::new(1).unwrap(),
            schema,
            Digest::new([0x20 + index as u8; 32]),
        )
        .unwrap(),
    )
}

#[allow(clippy::too_many_arguments)]
fn assert_recovery_artifact_differential(
    engine: &Engine,
    oracle: &RecoveryArtifactOracle,
    provider: ProviderCoordinate,
    effect: EffectId,
    component: ComponentId,
    artifact: RecoveryArtifactId,
    binding: cser_core::ArtifactBinding,
    owner: ArtifactOwner,
    expected_provider: OracleProviderPhase,
    expected_component: OracleComponentPhase,
    expected_artifact: OracleArtifactLeaseState,
) {
    let projection = oracle.projection();
    let model_provider = projection
        .providers
        .iter()
        .find(|record| {
            record.provider.get() == provider.provider().get()
                && record.generation.get() == provider.generation().get()
        })
        .unwrap();
    assert_eq!(model_provider.phase, expected_provider);
    let core_provider = engine.provider_generation_projection(provider).unwrap();
    assert_eq!(
        core_provider.live_component_bindings as u64,
        model_provider.live_components
    );
    assert_eq!(
        model_provider.live_effects,
        u64::from(model_provider.live_components != 0)
    );
    match expected_provider {
        OracleProviderPhase::Active => {
            assert!(matches!(core_provider.state, ProviderEffectState::Active))
        }
        OracleProviderPhase::EffectFenced => assert!(matches!(
            core_provider.state,
            ProviderEffectState::EffectFenced { .. }
        )),
        OracleProviderPhase::SettlementOnly => assert!(matches!(
            core_provider.state,
            ProviderEffectState::SettlementOnly { .. }
        )),
        OracleProviderPhase::Retired => assert!(matches!(
            core_provider.state,
            ProviderEffectState::Retired { .. }
        )),
    }

    let model_component = projection
        .components
        .iter()
        .find(|record| {
            record.effect.operation().get() == effect.operation().get()
                && record.effect.sequence() == effect.sequence()
                && record.component.get() == component.get()
        })
        .unwrap();
    assert_eq!(model_component.phase, expected_component);
    let core_component = engine.component(effect, component).unwrap();
    match expected_component {
        OracleComponentPhase::Staged => assert!(matches!(
            core_component.commit,
            CommitState::Registered | CommitState::Prepared
        )),
        OracleComponentPhase::CommitIntent => {
            assert_eq!(core_component.commit, CommitState::CommitIntentDurable);
        }
        OracleComponentPhase::Executed => {
            assert_eq!(core_component.commit, CommitState::CommitIntentDurable);
        }
        OracleComponentPhase::Outcome => {
            assert_eq!(core_component.commit, CommitState::Committed);
            assert!(matches!(
                core_component.outcome,
                OutcomeState::KnownSuccess(_)
            ));
        }
        OracleComponentPhase::Settled => {
            assert_eq!(core_component.commit, CommitState::Committed);
            assert!(matches!(
                core_component.outcome,
                OutcomeState::KnownSuccess(_)
            ));
            assert!(matches!(
                core_component.settlement,
                SettlementState::Settled
            ));
        }
        OracleComponentPhase::Aborted => {
            assert_eq!(core_component.settlement, SettlementState::Revoked);
        }
        OracleComponentPhase::Released => {
            assert_eq!(core_component.retirement, RetirementState::Released);
        }
    }
    assert_eq!(
        core_component.retirement == RetirementState::Retired
            || core_component.retirement == RetirementState::Released,
        model_component.physical_retired
    );
    if core_component.claim_count == 0 {
        assert!(!model_component.claims_retired);
    } else {
        assert_eq!(
            core_component.retained_claims == 0,
            model_component.claims_retired
        );
    }

    assert_eq!(
        model_component.effect.operation().get(),
        effect.operation().get()
    );
    assert_eq!(model_component.effect.sequence(), effect.sequence());

    let model_artifact = projection
        .artifacts
        .iter()
        .find(|record| record.lease.get() == artifact.get())
        .unwrap();
    assert_eq!(model_artifact.owner, owner);
    assert_eq!(
        model_artifact.catalog_digest,
        binding.catalog_digest().bytes()
    );
    assert_eq!(
        model_artifact.schema_digest,
        binding.schema_digest().bytes()
    );
    assert_eq!(
        model_artifact.verifier_set_digest,
        binding.verifier_set_digest().bytes()
    );
    assert_eq!(model_artifact.state, expected_artifact);
    assert_eq!(binding.artifact_id(), artifact);
    assert_eq!(binding.provider(), provider);
    assert_eq!(binding.operation(), effect.operation());
    assert_eq!(binding.effect(), effect);
    assert_eq!(binding.component(), component);
    assert_eq!(owner.catalog_digest, binding.catalog_digest().bytes());
    assert_eq!(owner.schema_digest, binding.schema_digest().bytes());
    assert_eq!(
        owner.verifier_set_digest,
        binding.verifier_set_digest().bytes()
    );
    assert_eq!(owner.closure_digest, binding.closure_digest().bytes());
    match expected_artifact {
        OracleArtifactLeaseState::Declared => {
            assert!(engine.artifact_lease(artifact).is_none());
        }
        OracleArtifactLeaseState::Pinned => assert!(matches!(
            engine.artifact_lease(artifact),
            Some(CoreArtifactLeaseState::Pinned { .. })
        )),
        OracleArtifactLeaseState::ReleaseAuthorized => assert!(matches!(
            engine.artifact_lease(artifact),
            Some(CoreArtifactLeaseState::ReleaseAuthorized { .. })
        )),
        OracleArtifactLeaseState::Released => assert!(matches!(
            engine.artifact_lease(artifact),
            Some(CoreArtifactLeaseState::Released { .. })
        )),
    }
    if expected_component == OracleComponentPhase::Released {
        let composite = engine.composite_effect(effect).unwrap();
        assert_eq!(composite.custodian, CustodyState::Released);
        assert!(engine.provider_obligations(provider).is_empty());
        let retained = engine
            .artifact_recovery_items()
            .into_iter()
            .find(|item| item.binding.artifact_id() == artifact)
            .expect("released provenance must retain the artifact binding");
        assert_eq!(retained.binding, binding);
        assert_eq!(retained.lease, engine.artifact_lease(artifact).unwrap());
    }
    assert!(oracle.check_invariants());
}

fn tx<C: Into<cser_core::Command>>(
    engine: &mut Engine,
    request: C,
) -> Result<cser_core::TransitionReceipt, CoreError> {
    engine.transact_volatile(request)
}

fn durable_tx<C: Into<cser_core::Command>>(
    engine: &mut Engine,
    journal: &mut Vec<u8>,
    request: C,
) -> cser_core::TransitionReceipt {
    engine
        .transact(request, |record| {
            journal.extend_from_slice(record.bytes());
            Ok::<(), ()>(())
        })
        .unwrap()
}

#[test]
fn required_artifact_core_matches_oracle_through_pin_settle_release_and_retire() {
    let value = 78_001;
    let catalog = catalog();
    let world_core = WorldId::new(WORLD).unwrap();
    let provider = provider(world_core);
    let mut engine = Engine::new(
        world_core,
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let mut journal = Vec::new();
    durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::RegisterProviderGeneration {
            coordinate: provider,
            catalog_digest: catalog.digest(),
            verifier_bindings: provider_verifiers(&catalog),
        },
    );
    durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::BindArtifactReceiptVerifiers {
            coordinate: provider,
            receipts: artifact_receipts(),
        },
    );
    let effect = EffectId::new(OperationId::new(value).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(value).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin: actor,
            kind: id(COMPOSITE, CompositeKindId::new),
            charge_account: cser_core::ChargeAccountId::new(value).unwrap(),
            bindings: vec![
                ComponentProviderBinding::new(id(COMPONENT, ComponentId::new), provider)
                    .with_artifact(ArtifactAdmission::new(
                        RecoveryArtifactId::new(value + 2).unwrap(),
                        Digest::new([0x51; 32]),
                        Digest::new([0x52; 32]),
                    )),
            ],
        },
    );
    let component = id(COMPONENT, ComponentId::new);
    let artifact = RecoveryArtifactId::new(value + 2).unwrap();
    let world = OracleWorldId::new(WORLD).unwrap();
    let oracle_provider = OracleProviderId::new(provider.provider().get()).unwrap();
    let oracle_generation = OracleProviderGeneration::new(provider.generation().get()).unwrap();
    let oracle_effect = OracleEffectId::new(
        OracleOperationId::new(effect.operation().get()).unwrap(),
        effect.sequence(),
    )
    .unwrap();
    let oracle_component = OracleComponentId::new(component.get()).unwrap();
    let oracle_artifact = OracleArtifactId::new(artifact.get()).unwrap();
    let mut oracle = RecoveryArtifactOracle::new(world);
    oracle
        .register_provider(oracle_provider, oracle_generation)
        .unwrap();
    oracle
        .admit_effect(
            oracle_effect,
            oracle_provider,
            oracle_generation,
            &[oracle_component],
        )
        .unwrap();

    let pin_challenge = engine.artifact_pin_challenge(effect, component).unwrap();
    let binding = pin_challenge.binding();
    let verifier_set_digest = engine
        .provider_generation_projection(provider)
        .unwrap()
        .verifier_set_digest;
    let owner = ArtifactOwner {
        world,
        provider: oracle_provider,
        generation: oracle_generation,
        operation: OracleOperationId::new(effect.operation().get()).unwrap(),
        effect: oracle_effect,
        component: oracle_component,
        catalog_digest: binding.catalog_digest().bytes(),
        schema_digest: binding.schema_digest().bytes(),
        verifier_set_digest: verifier_set_digest.bytes(),
        closure_digest: binding.closure_digest().bytes(),
    };
    oracle.require_artifact(oracle_artifact, owner).unwrap();
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::Active,
        OracleComponentPhase::Staged,
        OracleArtifactLeaseState::Declared,
    );

    durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::AddComponentClaim {
            effect,
            component,
            actor,
            claim: ClaimId::new(value + 2).unwrap(),
            kind: id(CLAIM, ClaimKindId::new),
            scope: ClaimScope::Logical,
            resource: ResourceId::new(value + 2).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        },
    );
    durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::PrepareCompositeEffect { effect, actor },
    );
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::Active,
        OracleComponentPhase::Staged,
        OracleArtifactLeaseState::Declared,
    );

    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::RecordComponentCommitIntent {
                effect,
                component,
                actor,
                operation: Digest::new([0x78; 32]),
            },
        ),
        Err(CoreError::ArtifactNotPinned)
    );
    assert_eq!(
        oracle.commit_intent(oracle_effect, oracle_component),
        Err(cser_model::recovery_artifact_oracle::ArtifactError::ArtifactNotPinned)
    );
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::Active,
        OracleComponentPhase::Staged,
        OracleArtifactLeaseState::Declared,
    );

    let pin = engine
        .verify_artifact_pin(
            effect,
            component,
            &AcceptPin(artifact_receipts().pin()),
            &(),
        )
        .unwrap();
    durable_tx(&mut engine, &mut journal, pin.record());
    oracle.pin_artifact(oracle_artifact, owner).unwrap();
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::Active,
        OracleComponentPhase::Staged,
        OracleArtifactLeaseState::Pinned,
    );

    let intent = match durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::RecordComponentCommitIntent {
            effect,
            component,
            actor,
            operation: Digest::new([0x78; 32]),
        },
    )
    .into_output()
    {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    oracle
        .commit_intent(oracle_effect, oracle_component)
        .unwrap();
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::Active,
        OracleComponentPhase::CommitIntent,
        OracleArtifactLeaseState::Pinned,
    );

    let commit_verifier = AcceptEffectFact {
        identity: scoped_identity(
            &catalog,
            id(COMMIT_VERIFIER, cser_core::VerifierId::new),
            id(COMMIT_SCHEMA, ReceiptSchemaId::new),
        ),
        outcome: Some(ExternalOutcome::Success),
        digest: Digest::new([0x7a; 32]),
    };
    let outcome = engine
        .verify_commit_outcome(&intent, &commit_verifier, &())
        .unwrap();
    durable_tx(
        &mut engine,
        &mut journal,
        intent.acknowledge(outcome).unwrap(),
    );
    oracle.execute(oracle_effect, oracle_component).unwrap();
    oracle
        .record_outcome(oracle_effect, oracle_component)
        .unwrap();
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::Active,
        OracleComponentPhase::Outcome,
        OracleArtifactLeaseState::Pinned,
    );

    durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::FenceProviderEffects {
            coordinate: provider,
            expected_epoch: 1,
        },
    );
    oracle
        .fence_provider(oracle_provider, oracle_generation)
        .unwrap();
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::EffectFenced,
        OracleComponentPhase::Outcome,
        OracleArtifactLeaseState::Pinned,
    );
    durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::EnterProviderSettlementOnly {
            coordinate: provider,
            expected_epoch: 2,
        },
    );
    oracle
        .enter_settlement_only(oracle_provider, oracle_generation)
        .unwrap();

    let settlement = match durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::ClaimComponentSettlement {
            effect,
            component,
            claimant: actor,
        },
    )
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    let settlement = match durable_tx(
        &mut engine,
        &mut journal,
        settlement
            .record_apply_intent(Digest::new([0x7b; 32]))
            .unwrap(),
    )
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected apply-intent claim, got {other:?}"),
    };
    let apply_verifier = AcceptEffectFact {
        identity: commit_verifier.identity,
        outcome: None,
        digest: Digest::new([0x7c; 32]),
    };
    let applied = engine
        .verify_apply_completion(&settlement, &apply_verifier, &())
        .unwrap();
    let settlement = match durable_tx(
        &mut engine,
        &mut journal,
        settlement.record_applied(applied).unwrap(),
    )
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected applied claim, got {other:?}"),
    };
    let acknowledgement = engine
        .verify_settlement_ack(&settlement, &apply_verifier, &())
        .unwrap();
    durable_tx(
        &mut engine,
        &mut journal,
        settlement.settle(acknowledgement).unwrap(),
    );
    oracle.settle(oracle_effect, oracle_component).unwrap();
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::SettlementOnly,
        OracleComponentPhase::Settled,
        OracleArtifactLeaseState::Pinned,
    );

    let committed_freshness = engine.freshness();
    let next_freshness = Freshness::new(
        BootGeneration::new(2).unwrap(),
        committed_freshness.registry(),
        committed_freshness.device(),
        JournalGeneration::new(2).unwrap(),
    );
    let recovery_binding = RecoveryBinding::new(
        RecoveryProfile::current(),
        world_core,
        CatalogSet::new(std::slice::from_ref(&catalog))
            .unwrap()
            .digest(),
        committed_freshness.registry(),
    )
    .unwrap();
    let anchor = RecoveryAnchor::from_trusted_provider(
        recovery_binding,
        committed_freshness,
        next_freshness,
        engine.revision(),
        engine.head(),
        engine.projection_digest(),
    )
    .unwrap();
    engine = Engine::recover(
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        anchor,
        &journal,
    )
    .unwrap()
    .into_engine();
    durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::CheckpointRecovery {
            boot: next_freshness.boot(),
            journal: next_freshness.journal(),
            device: next_freshness.device(),
        },
    );
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::SettlementOnly,
        OracleComponentPhase::Settled,
        OracleArtifactLeaseState::Pinned,
    );

    let evidence_verifier = AcceptEvidence(scoped_identity(
        &catalog,
        id(EVIDENCE_VERIFIER, cser_core::VerifierId::new),
        id(EVIDENCE_SCHEMA, ReceiptSchemaId::new),
    ));
    let evidence = engine
        .verify_component_retirement_evidence(
            effect,
            component,
            ClaimId::new(value + 2).unwrap(),
            id(EVIDENCE_KIND, EvidenceKindId::new),
            &evidence_verifier,
            &(),
        )
        .unwrap();
    durable_tx(&mut engine, &mut journal, evidence.submit());
    oracle
        .retire_physical(oracle_effect, oracle_component)
        .unwrap();
    oracle
        .retire_claims(oracle_effect, oracle_component)
        .unwrap();
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::SettlementOnly,
        OracleComponentPhase::Settled,
        OracleArtifactLeaseState::Pinned,
    );

    let core_permit = match durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::AuthorizeArtifactRelease { effect, component },
    )
    .into_output()
    {
        TransitionOutput::ArtifactReleasePermit(permit) => permit,
        other => panic!("expected artifact release permit, got {other:?}"),
    };
    let oracle_permit = oracle
        .authorize_artifact_release(oracle_artifact, owner)
        .unwrap();
    assert_eq!(core_permit.binding(), binding);
    let reissued_core_permit = engine.artifact_release_permit(effect, component).unwrap();
    assert_eq!(reissued_core_permit.binding(), core_permit.binding());
    assert_eq!(reissued_core_permit.pin_stamp(), core_permit.pin_stamp());
    assert_eq!(
        reissued_core_permit.release_operation(),
        core_permit.release_operation()
    );
    assert_eq!(reissued_core_permit.nonce(), core_permit.nonce());
    assert_eq!(oracle_permit.owner(), owner);
    assert_eq!(oracle_permit.lease().get(), artifact.get());
    assert_eq!(
        oracle
            .reissue_release_permit(oracle_artifact, owner)
            .unwrap(),
        oracle_permit
    );
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::SettlementOnly,
        OracleComponentPhase::Settled,
        OracleArtifactLeaseState::ReleaseAuthorized,
    );

    let verified = engine
        .verify_artifact_release(
            effect,
            component,
            &AcceptRelease(artifact_receipts().release()),
            &(),
        )
        .unwrap();
    durable_tx(&mut engine, &mut journal, verified.confirm());
    oracle.confirm_artifact_released(oracle_permit).unwrap();
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::SettlementOnly,
        OracleComponentPhase::Settled,
        OracleArtifactLeaseState::Released,
    );

    durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::ReleaseCompositeEffect { effect },
    );
    oracle
        .release_component(oracle_effect, oracle_component)
        .unwrap();
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::SettlementOnly,
        OracleComponentPhase::Released,
        OracleArtifactLeaseState::Released,
    );

    durable_tx(
        &mut engine,
        &mut journal,
        CommandRequest::RetireProviderEffects {
            coordinate: provider,
            expected_epoch: 3,
        },
    );
    oracle
        .retire_provider(oracle_provider, oracle_generation)
        .unwrap();
    assert_recovery_artifact_differential(
        &engine,
        &oracle,
        provider,
        effect,
        component,
        artifact,
        binding,
        owner,
        OracleProviderPhase::Retired,
        OracleComponentPhase::Released,
        OracleArtifactLeaseState::Released,
    );
}

#[test]
fn required_admission_without_artifact_is_rejected() {
    let (mut engine, catalog, provider) = registered_engine();
    let effect = EffectId::new(OperationId::new(71_001).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(71_001).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::AdmitScopedCompositeEffect {
                effect,
                origin: actor,
                kind: id(COMPOSITE, CompositeKindId::new),
                charge_account: cser_core::ChargeAccountId::new(71_001).unwrap(),
                bindings: vec![ComponentProviderBinding::new(
                    id(COMPONENT, ComponentId::new),
                    provider,
                )],
            },
        ),
        Err(CoreError::ArtifactRequired)
    );
    assert_eq!(
        engine.catalog_set_digest(),
        CatalogSet::new(std::slice::from_ref(&catalog))
            .unwrap()
            .digest()
    );
    assert!(engine.composite_effect(effect).is_none());
}

#[test]
fn scoped_admission_rejects_duplicate_artifact_ids_before_state_mutation() {
    let value = 71_101;
    let (mut engine, catalog, provider) = registered_engine_with_catalog(mixed_catalog());
    let effect = EffectId::new(OperationId::new(value).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(value).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    let duplicate = ArtifactAdmission::new(
        RecoveryArtifactId::new(value + 2).unwrap(),
        Digest::new([0x61; 32]),
        Digest::new([0x62; 32]),
    );
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::AdmitScopedCompositeEffect {
                effect,
                origin: actor,
                kind: id(COMPOSITE, CompositeKindId::new),
                charge_account: cser_core::ChargeAccountId::new(value).unwrap(),
                bindings: vec![
                    ComponentProviderBinding::new(id(COMPONENT, ComponentId::new), provider)
                        .with_artifact(duplicate),
                    ComponentProviderBinding::new(id(COMPONENT_TWO, ComponentId::new), provider)
                        .with_artifact(duplicate),
                ],
            },
        ),
        Err(CoreError::ArtifactBindingMismatch)
    );
    assert!(engine.composite_effect(effect).is_none());
    assert_eq!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .live_component_bindings,
        0
    );
    assert_eq!(
        engine.catalog_set_digest(),
        CatalogSet::new(std::slice::from_ref(&catalog))
            .unwrap()
            .digest()
    );
}

#[test]
fn unpinned_component_commit_intent_is_rejected() {
    let (mut engine, _catalog, provider, effect, actor) = fixture(72_001);
    prepare(&mut engine, effect, actor, 72_003);
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::RecordComponentCommitIntent {
                effect,
                component: id(COMPONENT, ComponentId::new),
                actor,
                operation: Digest::new([0x73; 32]),
            },
        ),
        Err(CoreError::ArtifactNotPinned)
    );
    assert_eq!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .live_component_bindings,
        1
    );
    assert_eq!(
        engine
            .component(effect, id(COMPONENT, ComponentId::new))
            .unwrap()
            .commit,
        CommitState::Prepared
    );
}

#[test]
fn artifact_pin_requires_exact_verifier_identity() {
    let (engine, _catalog, _provider, effect, _actor) = fixture(73_001);
    let expected = artifact_receipts().pin();
    let wrong = VerifierBinding::new(
        expected.verifier(),
        expected.generation(),
        expected.receipt_schema(),
        Digest::new([0xee; 32]),
    )
    .unwrap();
    let revision = engine.revision();
    assert_eq!(
        engine.verify_artifact_pin(
            effect,
            id(COMPONENT, ComponentId::new),
            &AcceptPin(wrong),
            &(),
        ),
        Err(CoreError::UnknownVerifier)
    );
    assert_eq!(engine.revision(), revision);
}

#[test]
fn pin_then_component_commit_intent_is_viable() {
    let (mut engine, _catalog, _provider, effect, actor) = fixture(74_001);
    prepare(&mut engine, effect, actor, 74_003);
    pin(&mut engine, effect);
    let receipt = tx(
        &mut engine,
        CommandRequest::RecordComponentCommitIntent {
            effect,
            component: id(COMPONENT, ComponentId::new),
            actor,
            operation: Digest::new([0x75; 32]),
        },
    )
    .unwrap();
    assert_eq!(receipt.event(), TransitionEvent::CommitIntentDurable);
    assert!(matches!(
        receipt.into_output(),
        TransitionOutput::CommitIntent(intent) if intent.component() == id(COMPONENT, ComponentId::new)
    ));
    assert_eq!(
        engine
            .component(effect, id(COMPONENT, ComponentId::new))
            .unwrap()
            .commit,
        CommitState::CommitIntentDurable
    );
}

#[test]
fn nonterminal_component_cannot_authorize_artifact_release() {
    let (mut engine, _catalog, _provider, effect, actor) = fixture(75_001);
    prepare(&mut engine, effect, actor, 75_003);
    pin(&mut engine, effect);
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::AuthorizeArtifactRelease {
                effect,
                component: id(COMPONENT, ComponentId::new),
            },
        ),
        Err(CoreError::ArtifactNotReleasable)
    );
}

#[test]
fn abort_unpinned_required_artifact_releases_scoped_binding() {
    let (mut engine, _catalog, provider, effect, _actor) = fixture(75_101);
    tx(
        &mut engine,
        CommandRequest::FenceProviderEffects {
            coordinate: provider,
            expected_epoch: 1,
        },
    )
    .unwrap();
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::EnterProviderSettlementOnly {
                coordinate: provider,
                expected_epoch: 2,
            },
        ),
        Err(CoreError::ProviderEffectsLive)
    );
    assert_eq!(
        engine.artifact_lease(RecoveryArtifactId::new(75_103).unwrap()),
        None
    );
    tx(&mut engine, CommandRequest::AbortUnescapedEffect { effect }).unwrap();
    assert_eq!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .live_component_bindings,
        0
    );
    tx(
        &mut engine,
        CommandRequest::EnterProviderSettlementOnly {
            coordinate: provider,
            expected_epoch: 2,
        },
    )
    .unwrap();
    tx(
        &mut engine,
        CommandRequest::RetireProviderEffects {
            coordinate: provider,
            expected_epoch: 3,
        },
    )
    .unwrap();
    assert!(matches!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .state,
        cser_core::ProviderEffectState::Retired { epoch: 4 }
    ));
}

#[test]
fn abort_mixed_artifacts_retracts_only_unpinned_placeholders() {
    let value = 77_101;
    let (mut engine, _catalog, provider, effect) = mixed_fixture(value);
    let first_component = id(COMPONENT, ComponentId::new);
    let second_component = id(COMPONENT_TWO, ComponentId::new);
    pin_component(&mut engine, effect, first_component);
    tx(
        &mut engine,
        CommandRequest::FenceProviderEffects {
            coordinate: provider,
            expected_epoch: 1,
        },
    )
    .unwrap();
    tx(&mut engine, CommandRequest::AbortUnescapedEffect { effect }).unwrap();

    assert_eq!(
        engine
            .artifact_lease(RecoveryArtifactId::new(value + 2).unwrap())
            .unwrap()
            .pin_stamp(),
        Digest::new([0x71; 32])
    );
    assert_eq!(
        engine.artifact_lease(RecoveryArtifactId::new(value + 3).unwrap()),
        None
    );
    let second = engine.component(effect, second_component).unwrap();
    assert_eq!(second.settlement, cser_core::SettlementState::Revoked);
    assert_eq!(second.retirement, cser_core::RetirementState::Retired);
    assert_eq!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .live_component_bindings,
        2
    );

    tx(
        &mut engine,
        CommandRequest::AuthorizeArtifactRelease {
            effect,
            component: first_component,
        },
    )
    .unwrap();
    let verified = engine
        .verify_artifact_release(
            effect,
            first_component,
            &AcceptRelease(artifact_receipts().release()),
            &(),
        )
        .unwrap();
    tx(&mut engine, verified.confirm()).unwrap();
    tx(
        &mut engine,
        CommandRequest::ReleaseCompositeEffect { effect },
    )
    .unwrap();
    assert_eq!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .live_component_bindings,
        0
    );
    tx(
        &mut engine,
        CommandRequest::EnterProviderSettlementOnly {
            coordinate: provider,
            expected_epoch: 2,
        },
    )
    .unwrap();
    tx(
        &mut engine,
        CommandRequest::RetireProviderEffects {
            coordinate: provider,
            expected_epoch: 3,
        },
    )
    .unwrap();
}

#[test]
fn abort_unescaped_then_release_reissues_the_same_permit_and_confirms_once() {
    let (mut engine, _catalog, provider, effect, _actor) = fixture(76_001);
    pin(&mut engine, effect);
    tx(
        &mut engine,
        CommandRequest::FenceProviderEffects {
            coordinate: provider,
            expected_epoch: 1,
        },
    )
    .unwrap();
    let abort = engine
        .transact_volatile(CommandRequest::AbortUnescapedEffect { effect })
        .unwrap();
    assert_eq!(abort.event(), TransitionEvent::Revoked);
    let component = engine
        .component(effect, id(COMPONENT, ComponentId::new))
        .unwrap();
    assert_eq!(component.retirement, cser_core::RetirementState::Retired);
    assert_eq!(component.settlement, cser_core::SettlementState::Revoked);
    assert_eq!(
        engine
            .artifact_lease(RecoveryArtifactId::new(76_003).unwrap())
            .unwrap()
            .pin_stamp(),
        Digest::new([0x71; 32])
    );
    assert_eq!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .live_component_bindings,
        1
    );
    tx(
        &mut engine,
        CommandRequest::EnterProviderSettlementOnly {
            coordinate: provider,
            expected_epoch: 2,
        },
    )
    .unwrap();
    assert!(matches!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .state,
        ProviderEffectState::SettlementOnly { .. }
    ));

    let permit = match tx(
        &mut engine,
        CommandRequest::AuthorizeArtifactRelease {
            effect,
            component: id(COMPONENT, ComponentId::new),
        },
    )
    .unwrap()
    .into_output()
    {
        TransitionOutput::ArtifactReleasePermit(permit) => permit,
        other => panic!("unexpected output: {other:?}"),
    };
    let reissued = engine
        .artifact_release_permit(effect, id(COMPONENT, ComponentId::new))
        .unwrap();
    assert_eq!(permit.exact_tuple(), reissued.exact_tuple());

    let verified = engine
        .verify_artifact_release(
            effect,
            id(COMPONENT, ComponentId::new),
            &AcceptRelease(artifact_receipts().release()),
            &(),
        )
        .unwrap();
    assert_eq!(verified.permit().exact_tuple(), permit.exact_tuple());
    tx(&mut engine, verified.confirm()).unwrap();
    assert_eq!(
        engine.artifact_release_challenge(effect, id(COMPONENT, ComponentId::new)),
        Err(CoreError::ArtifactReleaseMismatch)
    );
    tx(
        &mut engine,
        CommandRequest::ReleaseCompositeEffect { effect },
    )
    .unwrap();
    assert_eq!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .live_component_bindings,
        0
    );
}
