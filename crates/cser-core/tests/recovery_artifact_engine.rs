use cser_core::{
    AdoptionPolicy, ArtifactAdmission, ArtifactPinChallenge, ArtifactPinVerifier,
    ArtifactReceiptBindings, ArtifactReleaseChallenge, ArtifactReleaseVerifier, BootGeneration,
    ClaimCardinality, ClaimKindId, ClaimScope, CommandRequest, CommitState, ComponentId,
    ComponentProviderBinding, CompositeComponentSpec, CompositeKindId, CoreError, CoreLimits,
    CreditClassId, DeviceGeneration, DeviceGenerationEffect, Digest, DomainCatalog,
    DomainCatalogBuilder, DomainId, EffectId, Engine, EvidenceKindId, EvidenceRule, Freshness,
    FreshnessAxes, JournalGeneration, ObligationKindId, ObligationPolicy, ObligationReceipts,
    ObligationSpec, OperationId, PrincipalId, PrincipalIncarnation, ProviderCoordinate,
    ProviderGeneration, ProviderId, ReceiptBinding, ReceiptSchemaId, RecoveryArtifactId,
    RecoveryArtifactPolicy, RegistryInstance, ResourceGeneration, ResourceId, RootId,
    TransitionEvent, TransitionOutput, VerificationError, VerifierBinding, VerifierGeneration,
    VerifierIdentity, WorldId,
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
        1,
        DeviceGeneration::new(1).unwrap(),
        JournalGeneration::new(1).unwrap(),
    )
    .unwrap()
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
        catalog.clone(),
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
    PrincipalIncarnation,
) {
    let (mut engine, catalog, provider) = registered_engine();
    let effect = EffectId::new(RootId::new(effect_value).unwrap(), 1).unwrap();
    let actor = PrincipalIncarnation::new(PrincipalId::new(effect_value).unwrap(), 1).unwrap();
    let operation = OperationId::new(effect_value + 1).unwrap();
    let admission = ArtifactAdmission::new(
        RecoveryArtifactId::new(effect_value + 2).unwrap(),
        Digest::new([0x51; 32]),
        Digest::new([0x52; 32]),
    );
    engine
        .transact_volatile(CommandRequest::AdmitScopedCompositeEffect {
            effect,
            operation,
            origin: actor,
            binding_generation: 1,
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
    let effect = EffectId::new(RootId::new(effect_value).unwrap(), 1).unwrap();
    let actor = PrincipalIncarnation::new(PrincipalId::new(effect_value).unwrap(), 1).unwrap();
    let operation = OperationId::new(effect_value + 1).unwrap();
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
            operation,
            origin: actor,
            binding_generation: 1,
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

fn prepare(engine: &mut Engine, effect: EffectId, actor: PrincipalIncarnation, value: u64) {
    engine
        .transact_volatile(CommandRequest::AddComponentClaim {
            effect,
            component: id(COMPONENT, ComponentId::new),
            actor,
            binding_generation: 1,
            claim: cser_core::ClaimId::new(value).unwrap(),
            kind: id(CLAIM, ClaimKindId::new),
            scope: ClaimScope::Logical,
            resource: ResourceId::new(value).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        })
        .unwrap();
    engine
        .transact_volatile(CommandRequest::PrepareCompositeEffect {
            effect,
            actor,
            binding_generation: 1,
        })
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

fn tx<C: Into<cser_core::Command>>(
    engine: &mut Engine,
    request: C,
) -> Result<cser_core::TransitionReceipt, CoreError> {
    engine.transact_volatile(request)
}

#[test]
fn required_admission_without_artifact_is_rejected() {
    let (mut engine, catalog, provider) = registered_engine();
    let effect = EffectId::new(RootId::new(71_001).unwrap(), 1).unwrap();
    let actor = PrincipalIncarnation::new(PrincipalId::new(71_001).unwrap(), 1).unwrap();
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::AdmitScopedCompositeEffect {
                effect,
                operation: OperationId::new(71_002).unwrap(),
                origin: actor,
                binding_generation: 1,
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
    assert_eq!(engine.catalog_digest(), catalog.digest());
    assert!(engine.composite_effect(effect).is_none());
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
                binding_generation: 1,
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
            binding_generation: 1,
            operation: Digest::new([0x75; 32]),
        },
    )
    .unwrap();
    assert_eq!(receipt.event(), TransitionEvent::CommitIntentDurable);
    assert!(matches!(
        receipt.into_output(),
        TransitionOutput::CommitIntent(intent) if intent.component() == Some(id(COMPONENT, ComponentId::new))
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
    tx(&mut engine, CommandRequest::AbortUnescapedEffect { effect }).unwrap();
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
