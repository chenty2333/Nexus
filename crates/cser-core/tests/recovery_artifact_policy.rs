use cser_core::{
    AGENT_OPERATION_COMPOSITE, AdoptionPolicy, ClaimCardinality, ClaimScopePolicy, ComponentId,
    CompositeComponentSpec, CompositeKindId, CreditClassId, DomainCatalog, DomainCatalogBuilder,
    DomainId, EvidenceKindId, EvidenceRule, FreshnessAxes, HARNESS_COMPONENT_ARTIFACT_CLOSURE,
    HARNESS_COMPONENT_RETAINED_PROVIDER_GENERATION, HARNESS_OPERATION_COMPOSITE, ObligationKindId,
    ObligationPolicy, ObligationReceipts, ObligationSpec, ReceiptBinding, ReceiptSchemaId,
    RecoveryArtifactPolicy, VerifierId, standard_catalog,
};

fn tiny_catalog(policy: RecoveryArtifactPolicy) -> DomainCatalog {
    let domain = DomainId::new(90).unwrap();
    let obligation = ObligationKindId::new(90).unwrap();
    let claim = cser_core::ClaimKindId::new(90).unwrap();
    let component = ComponentId::new(90).unwrap();
    let credit = CreditClassId::new(90).unwrap();
    let verifier = VerifierId::new(90).unwrap();
    let receipt_schema = ReceiptSchemaId::new(90).unwrap();
    let evidence = EvidenceKindId::new(90).unwrap();
    let freshness = FreshnessAxes::BOOT
        .union(FreshnessAxes::REGISTRY)
        .union(FreshnessAxes::JOURNAL);

    DomainCatalogBuilder::new()
        .credit_class(credit, 1)
        .unwrap()
        .obligation(
            ObligationSpec::new(
                domain,
                obligation,
                ObligationPolicy::SuccessorSettlement,
                AdoptionPolicy::UncommittedOnly,
                ObligationReceipts::successor_settlement(
                    ReceiptBinding::new(verifier, receipt_schema),
                    ReceiptBinding::new(verifier, receipt_schema),
                    ReceiptBinding::new(verifier, receipt_schema),
                ),
                1,
            ),
            &[ClaimCardinality::new(claim, 1, 1).unwrap()],
        )
        .unwrap()
        .claim(
            domain,
            claim,
            credit,
            ClaimScopePolicy::Logical,
            &[EvidenceRule::logical(
                evidence,
                ReceiptBinding::new(verifier, receipt_schema),
                freshness,
            )],
        )
        .unwrap()
        .composite(
            CompositeKindId::new(90).unwrap(),
            &[CompositeComponentSpec::new(component, domain, obligation)
                .with_artifact_policy(policy)],
        )
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn component_policy_defaults_and_is_bound_into_catalog_digest() {
    let component = CompositeComponentSpec::new(
        ComponentId::new(1).unwrap(),
        DomainId::new(1).unwrap(),
        ObligationKindId::new(1).unwrap(),
    );
    assert_eq!(
        component.recovery_artifact_policy(),
        RecoveryArtifactPolicy::NotRequired
    );
    assert_eq!(
        component
            .with_recovery_artifact_policy(RecoveryArtifactPolicy::Required)
            .artifact_policy(),
        RecoveryArtifactPolicy::Required
    );

    let not_required = tiny_catalog(RecoveryArtifactPolicy::NotRequired);
    let required = tiny_catalog(RecoveryArtifactPolicy::Required);
    assert_ne!(not_required.digest(), required.digest());
    assert_eq!(
        not_required
            .composite_rule(CompositeKindId::new(90).unwrap())
            .unwrap()
            .components()[0]
            .artifact_policy(),
        RecoveryArtifactPolicy::NotRequired
    );
    assert_eq!(
        required
            .composite_rule(CompositeKindId::new(90).unwrap())
            .unwrap()
            .components()[0]
            .artifact_policy(),
        RecoveryArtifactPolicy::Required
    );
}

#[test]
fn built_in_profiles_declare_their_artifact_boundary() {
    let standard = standard_catalog();
    for component in standard
        .composite_rule(AGENT_OPERATION_COMPOSITE)
        .unwrap()
        .components()
        .iter()
        .chain(
            standard
                .composite_rule(cser_core::DMA_ARENA_REUSE_COMPOSITE)
                .unwrap()
                .components()
                .iter(),
        )
    {
        assert_eq!(
            component.artifact_policy(),
            RecoveryArtifactPolicy::NotRequired
        );
    }

    let harness = cser_core::harness_catalog();
    let harness_rule = harness.composite_rule(HARNESS_OPERATION_COMPOSITE).unwrap();
    assert_eq!(
        harness_rule
            .component(HARNESS_COMPONENT_RETAINED_PROVIDER_GENERATION)
            .unwrap()
            .artifact_policy(),
        RecoveryArtifactPolicy::Required
    );
    assert_eq!(
        harness_rule
            .component(HARNESS_COMPONENT_ARTIFACT_CLOSURE)
            .unwrap()
            .artifact_policy(),
        RecoveryArtifactPolicy::Required
    );
    assert!(
        harness_rule
            .components()
            .iter()
            .filter(|component| {
                component.component() != HARNESS_COMPONENT_RETAINED_PROVIDER_GENERATION
                    && component.component() != HARNESS_COMPONENT_ARTIFACT_CLOSURE
            })
            .all(|component| component.artifact_policy() == RecoveryArtifactPolicy::NotRequired)
    );
}
