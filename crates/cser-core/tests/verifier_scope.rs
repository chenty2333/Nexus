use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration,
    CatalogSet, ClaimId, ClaimScope, CommandRequest, ComponentProviderBinding, CoreLimits,
    DeviceGeneration, Digest, EffectId, Engine, ExecutorCoordinate, ExecutorGeneration, ExecutorId,
    Freshness, JournalGeneration, OperationId, ProviderCoordinate, ProviderGeneration, ProviderId,
    REPLY_EVIDENCE_PUBLICATION_ACK, ReceiptVerifier, RegistryInstance, ResourceGeneration,
    ResourceId, VerificationError, VerifiedObservation, VerifierBinding, VerifierGeneration,
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

fn provider(world: u64, provider: u64, generation: u64) -> ProviderCoordinate {
    ProviderCoordinate::new(
        WorldId::new(world).unwrap(),
        ProviderId::new(provider).unwrap(),
        ProviderGeneration::new(generation).unwrap(),
    )
}

fn verifier_bindings(catalog: &cser_core::DomainCatalog) -> Vec<VerifierBinding> {
    catalog
        .verifier_class_bindings()
        .into_iter()
        .enumerate()
        .map(|(index, class)| {
            VerifierBinding::new(
                class.verifier(),
                VerifierGeneration::new(1).unwrap(),
                class.receipt_schema(),
                Digest::new([0x40u8.wrapping_add(index as u8); 32]),
            )
            .unwrap()
        })
        .collect()
}

fn scoped_engine(
    world: u64,
    provider_id: u64,
    effect_seed: u64,
) -> (Engine, EffectId, ProviderCoordinate) {
    let catalog = standard_catalog();
    let catalog_digest = catalog.digest();
    let coordinate = provider(world, provider_id, 1);
    let bindings = verifier_bindings(&catalog);
    let mut engine = Engine::new(
        WorldId::new(world).unwrap(),
        CatalogSet::new(&[catalog]).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    engine
        .transact_volatile(CommandRequest::RegisterProviderGeneration {
            coordinate,
            catalog_digest,
            verifier_bindings: bindings,
        })
        .unwrap();
    let operation = OperationId::new(effect_seed).unwrap();
    let effect = EffectId::new(operation, 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(effect_seed).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    engine
        .transact_volatile(CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin: actor,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: cser_core::ChargeAccountId::new(effect_seed).unwrap(),
            bindings: vec![
                ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, coordinate),
                ComponentProviderBinding::new(AGENT_COMPONENT_DMA, coordinate),
            ],
        })
        .unwrap();
    engine
        .transact_volatile(CommandRequest::AddComponentClaim {
            effect,
            component: AGENT_COMPONENT_REPLY,
            actor,
            claim: ClaimId::new(effect_seed).unwrap(),
            kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
            scope: ClaimScope::Logical,
            resource: ResourceId::new(effect_seed).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        })
        .unwrap();
    (engine, effect, coordinate)
}

#[derive(Clone, Copy)]
struct ScopeVerifier {
    identity: VerifierIdentity,
    expected_scope: cser_core::ProviderVerificationScope,
}

impl ReceiptVerifier for ScopeVerifier {
    type Receipt = ();

    fn identity(&self) -> VerifierIdentity {
        self.identity
    }

    fn verify(
        &self,
        challenge: &cser_core::EvidenceChallenge,
        _receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, VerificationError> {
        if challenge.verification_scope() != self.expected_scope {
            return Err(VerificationError::Rejected);
        }
        Ok(VerifiedObservation::new_bound(
            challenge.subject(),
            challenge.subject_binding(),
            challenge.current_observation(),
            challenge.current_binding(),
            Digest::new([0xa5; 32]),
        ))
    }
}

#[test]
fn scoped_challenge_and_verified_token_retain_exact_provider_scope() {
    let (engine, effect, coordinate) = scoped_engine(700, 701, 702);
    let claim = ClaimId::new(702).unwrap();
    let challenge = engine
        .component_evidence_challenge(
            effect,
            AGENT_COMPONENT_REPLY,
            claim,
            REPLY_EVIDENCE_PUBLICATION_ACK,
        )
        .unwrap();
    let scope = challenge.verification_scope();
    assert_eq!(scope.world(), WorldId::new(700).unwrap());
    assert_eq!(scope.provider(), coordinate);
    assert_eq!(scope.operation(), OperationId::new(702).unwrap());
    assert_eq!(scope.catalog_digest(), standard_catalog().digest());
    assert_eq!(
        challenge.expected_verifier_binding(),
        scope.verifier_binding()
    );

    let token = engine
        .verify_component_retirement_evidence(
            effect,
            AGENT_COMPONENT_REPLY,
            claim,
            REPLY_EVIDENCE_PUBLICATION_ACK,
            &ScopeVerifier {
                identity: VerifierIdentity::new_exact(scope.verifier_binding()),
                expected_scope: scope,
            },
            &(),
        )
        .unwrap();
    assert_eq!(token.verification_scope(), scope);

    let obligations = engine.provider_obligations(coordinate);
    assert_eq!(obligations.len(), 2);
    let reply = obligations
        .iter()
        .find(|item| item.component == AGENT_COMPONENT_REPLY)
        .unwrap();
    assert_eq!(reply.effect, effect);
    assert_eq!(reply.operation, OperationId::new(702).unwrap());
    assert_eq!(reply.catalog_digest, standard_catalog().digest());
    assert!(reply.artifact.is_none());
}

#[test]
fn verifier_rejects_cross_world_scope_replay_before_minting_evidence() {
    let (first, first_effect, _) = scoped_engine(710, 711, 712);
    let first_challenge = first
        .component_evidence_challenge(
            first_effect,
            AGENT_COMPONENT_REPLY,
            ClaimId::new(712).unwrap(),
            REPLY_EVIDENCE_PUBLICATION_ACK,
        )
        .unwrap();
    let first_scope = first_challenge.verification_scope();

    let (second, second_effect, _) = scoped_engine(720, 721, 722);
    let second_challenge = second
        .component_evidence_challenge(
            second_effect,
            AGENT_COMPONENT_REPLY,
            ClaimId::new(722).unwrap(),
            REPLY_EVIDENCE_PUBLICATION_ACK,
        )
        .unwrap();
    assert_ne!(first_scope, second_challenge.verification_scope());
    let verifier = ScopeVerifier {
        identity: VerifierIdentity::new_exact(
            second_challenge.verification_scope().verifier_binding(),
        ),
        expected_scope: first_scope,
    };
    assert_eq!(
        second.verify_component_retirement_evidence(
            second_effect,
            AGENT_COMPONENT_REPLY,
            ClaimId::new(722).unwrap(),
            REPLY_EVIDENCE_PUBLICATION_ACK,
            &verifier,
            &(),
        ),
        Err(cser_core::CoreError::VerificationFailed)
    );
}
