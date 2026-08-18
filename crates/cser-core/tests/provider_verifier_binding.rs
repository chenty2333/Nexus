use cser_core::{
    AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration, CatalogSet, ClaimScope,
    CommandRequest, ComponentProviderBinding, CoreError, CoreLimits, DeviceGeneration, Digest,
    DomainCatalog, EffectId, Engine, ExecutorCoordinate, ExecutorGeneration, ExecutorId, Freshness,
    JournalGeneration, ProviderCoordinate, ProviderGeneration, ProviderId,
    REPLY_CLAIM_PUBLICATION_SLOT, REPLY_EVIDENCE_PUBLICATION_ACK, REPLY_VERIFIER, ReceiptSchemaId,
    RecoveryAnchor, RecoveryBinding, RecoveryProfile, RegistryInstance, ResourceGeneration,
    ResourceId, TransitionDurability, VerifierBinding, VerifierGeneration, VerifierId,
    VerifierIdentity, WorldId, standard_catalog,
};

fn freshness() -> Freshness {
    Freshness::new(
        BootGeneration::new(1).unwrap(),
        RegistryInstance::new(1).unwrap(),
        DeviceGeneration::new(1).unwrap(),
        JournalGeneration::new(1).unwrap(),
    )
}

fn recovery_binding(
    world: WorldId,
    catalog: &DomainCatalog,
    freshness: Freshness,
) -> RecoveryBinding {
    RecoveryBinding::new(
        RecoveryProfile::current(),
        world,
        CatalogSet::new(std::slice::from_ref(catalog))
            .unwrap()
            .digest(),
        freshness.registry(),
    )
    .unwrap()
}

fn coordinate(world: u64, provider: u64, generation: u64) -> ProviderCoordinate {
    ProviderCoordinate::new(
        WorldId::new(world).unwrap(),
        ProviderId::new(provider).unwrap(),
        ProviderGeneration::new(generation).unwrap(),
    )
}

fn bindings(catalog: &DomainCatalog, generation: u64, implementation: u8) -> Vec<VerifierBinding> {
    catalog
        .verifier_class_bindings()
        .into_iter()
        .enumerate()
        .map(|(index, class)| {
            VerifierBinding::new(
                class.verifier(),
                VerifierGeneration::new(generation).unwrap(),
                class.receipt_schema(),
                Digest::new([implementation.wrapping_add(index as u8); 32]),
            )
            .unwrap()
        })
        .collect()
}

fn admit_one_component_effect(
    engine: &mut Engine,
    provider: ProviderCoordinate,
    effect_value: u64,
) -> (EffectId, cser_core::ComponentProviderBinding) {
    let effect = EffectId::new(cser_core::OperationId::new(effect_value).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(effect_value).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    let binding = ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, provider);
    engine
        .transact_volatile(CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin: actor,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: cser_core::ChargeAccountId::new(effect_value).unwrap(),
            bindings: vec![
                binding,
                ComponentProviderBinding::new(cser_core::AGENT_COMPONENT_DMA, provider),
            ],
        })
        .unwrap();
    engine
        .transact_volatile(CommandRequest::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_REPLY,
            actor,
            claim: cser_core::ClaimId::new(effect_value).unwrap(),
            kind: REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: ResourceId::new(effect_value).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        })
        .unwrap();
    (effect, binding)
}

#[derive(Clone, Copy)]
struct RejectingVerifier(VerifierIdentity);

impl cser_core::ReceiptVerifier for RejectingVerifier {
    type Receipt = ();

    fn identity(&self) -> VerifierIdentity {
        self.0
    }

    fn verify(
        &self,
        _challenge: &cser_core::EvidenceChallenge,
        _receipt: &Self::Receipt,
    ) -> Result<cser_core::VerifiedObservation, cser_core::VerificationError> {
        Err(cser_core::VerificationError::Rejected)
    }
}

struct Capture {
    journal: Vec<u8>,
}

impl TransitionDurability for Capture {
    type Error = ();

    fn persist_transition(
        &mut self,
        record: &cser_core::JournalRecord,
        _resulting_freshness: Freshness,
        _resulting_projection: Digest,
    ) -> Result<(), Self::Error> {
        self.journal.extend_from_slice(record.bytes());
        Ok(())
    }
}

#[test]
fn scoped_verifier_generation_and_implementation_mismatch_fail_without_mutation() {
    let world = WorldId::new(901).unwrap();
    let catalog = standard_catalog();
    let provider = coordinate(901, 902, 1);
    let exact = bindings(&catalog, 1, 0x30);
    let expected = exact
        .iter()
        .find(|binding| {
            binding.verifier() == REPLY_VERIFIER
                && binding.receipt_schema() == ReceiptSchemaId::new(1).unwrap()
        })
        .copied()
        .unwrap();
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
            verifier_bindings: exact,
        })
        .unwrap();
    let (effect, _) = admit_one_component_effect(&mut engine, provider, 9011);
    let challenge = engine
        .component_evidence_challenge(
            effect,
            AGENT_COMPONENT_REPLY,
            cser_core::ClaimId::new(9011).unwrap(),
            REPLY_EVIDENCE_PUBLICATION_ACK,
        )
        .unwrap();
    assert_eq!(challenge.expected_verifier_binding(), expected);
    let revision = engine.revision();
    let projection = engine.projection_digest();
    let wrong_generation = VerifierBinding::new(
        expected.verifier(),
        VerifierGeneration::new(expected.generation().get() + 1).unwrap(),
        expected.receipt_schema(),
        expected.implementation_digest(),
    )
    .unwrap();
    assert_eq!(
        engine.verify_component_retirement_evidence(
            effect,
            AGENT_COMPONENT_REPLY,
            cser_core::ClaimId::new(9011).unwrap(),
            REPLY_EVIDENCE_PUBLICATION_ACK,
            &RejectingVerifier(VerifierIdentity::new_exact(wrong_generation)),
            &(),
        ),
        Err(CoreError::StaleVerifierEpoch)
    );
    let wrong_implementation = VerifierBinding::new(
        expected.verifier(),
        expected.generation(),
        expected.receipt_schema(),
        Digest::new([0xee; 32]),
    )
    .unwrap();
    assert_eq!(
        engine.verify_component_retirement_evidence(
            effect,
            AGENT_COMPONENT_REPLY,
            cser_core::ClaimId::new(9011).unwrap(),
            REPLY_EVIDENCE_PUBLICATION_ACK,
            &RejectingVerifier(VerifierIdentity::new_exact(wrong_implementation)),
            &(),
        ),
        Err(CoreError::UnknownVerifier)
    );
    assert_eq!(engine.revision(), revision);
    assert_eq!(engine.projection_digest(), projection);
}

#[test]
fn verifier_rotation_waits_for_effect_retirement_without_rebinding_challenge() {
    let world = WorldId::new(903).unwrap();
    let catalog = standard_catalog();
    let provider = coordinate(903, 904, 1);
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
            verifier_bindings: bindings(&catalog, 1, 0x40),
        })
        .unwrap();
    let (effect, _) = admit_one_component_effect(&mut engine, provider, 9031);
    let before = engine
        .component_evidence_challenge(
            effect,
            AGENT_COMPONENT_REPLY,
            cser_core::ClaimId::new(9031).unwrap(),
            REPLY_EVIDENCE_PUBLICATION_ACK,
        )
        .unwrap();
    let next = coordinate(903, 904, 2);
    assert_eq!(
        engine.transact_volatile(CommandRequest::RegisterProviderGeneration {
            coordinate: next,
            catalog_digest: catalog.digest(),
            verifier_bindings: bindings(&catalog, 2, 0x60),
        }),
        Err(CoreError::ProviderLifecycleViolation)
    );
    let after = engine
        .component_evidence_challenge(
            effect,
            AGENT_COMPONENT_REPLY,
            cser_core::ClaimId::new(9031).unwrap(),
            REPLY_EVIDENCE_PUBLICATION_ACK,
        )
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .verifier_bindings,
        bindings(&catalog, 1, 0x40)
    );
}

#[test]
fn provider_checkpoint_roundtrip_retains_exact_verifier_set() {
    let world = WorldId::new(905).unwrap();
    let catalog = standard_catalog();
    let provider = coordinate(905, 906, 1);
    let exact = bindings(&catalog, 1, 0x70);
    let mut engine = Engine::new(
        world,
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let mut capture = Capture {
        journal: Vec::new(),
    };
    engine
        .transact_durable(
            CommandRequest::RegisterProviderGeneration {
                coordinate: provider,
                catalog_digest: catalog.digest(),
                verifier_bindings: exact.clone(),
            },
            &mut capture,
        )
        .unwrap();
    engine.compact_checkpoint_durable(&mut capture).unwrap();
    let next = Freshness::new(
        BootGeneration::new(2).unwrap(),
        RegistryInstance::new(1).unwrap(),
        DeviceGeneration::new(1).unwrap(),
        JournalGeneration::new(2).unwrap(),
    );
    let recovered = Engine::recover(
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            recovery_binding(world, &catalog, freshness()),
            freshness(),
            next,
            engine.revision(),
            engine.head(),
            engine.projection_digest(),
        )
        .unwrap(),
        &capture.journal,
    )
    .unwrap()
    .into_engine();
    assert_eq!(
        recovered
            .provider_generation_projection(provider)
            .unwrap()
            .verifier_bindings,
        exact
    );
}

#[test]
fn provider_registration_rejects_raw_or_wrong_verifier_classes() {
    let world = WorldId::new(907).unwrap();
    let catalog = standard_catalog();
    let mut engine = Engine::new(
        world,
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let wrong = VerifierBinding::new(
        VerifierId::new(99).unwrap(),
        VerifierGeneration::new(1).unwrap(),
        ReceiptSchemaId::new(99).unwrap(),
        Digest::new([0x99; 32]),
    )
    .unwrap();
    assert_eq!(
        engine.transact_volatile(CommandRequest::RegisterProviderGeneration {
            coordinate: coordinate(907, 908, 1),
            catalog_digest: catalog.digest(),
            verifier_bindings: vec![wrong],
        }),
        Err(CoreError::VerifierSetMismatch)
    );
    assert_eq!(engine.revision(), 0);
}
