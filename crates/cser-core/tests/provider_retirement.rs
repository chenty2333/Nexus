use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration,
    ChildDescriptorV1, ChildDescriptorVerifier, ClaimId, ClaimScope, CommandRequest,
    ComponentProviderBinding, CoreError, CoreLimits, DeviceGeneration, Digest, DomainCatalog,
    EffectId, EffectReceiptVerifier, Engine, ExternalOutcome, Freshness, JournalGeneration,
    OperationId, PrincipalId, PrincipalIncarnation, ProviderCoordinate, ProviderEffectState,
    ProviderGeneration, ProviderId, RegistryInstance, ResourceGeneration, ResourceId, RootId,
    TOOL_CLAIM_OUTCOME_SLOT, TOOL_COMMIT_RECEIPT_SCHEMA, TOOL_HANDOFF_CHILD_COMPOSITE,
    TOOL_HANDOFF_COMPONENT, TOOL_HANDOFF_SOURCE_COMPONENT, TOOL_HANDOFF_SOURCE_COMPOSITE,
    TOOL_VERIFIER, TransitionOutput, VerifiedEffectObservation, VerifierBinding,
    VerifierGeneration, VerifierIdentity, WorldId, standard_catalog, tool_dma_catalog,
};

struct AcceptDescriptor;

impl ChildDescriptorVerifier for AcceptDescriptor {
    type Receipt = ();

    fn verify_child_descriptor(
        &self,
        _descriptor: ChildDescriptorV1,
        _receipt: &Self::Receipt,
    ) -> Result<Digest, cser_core::VerificationError> {
        Ok(Digest::new([0xa5; 32]))
    }
}

struct AcceptEffect;

impl EffectReceiptVerifier for AcceptEffect {
    type Receipt = ();

    fn identity(&self) -> VerifierIdentity {
        VerifierIdentity::new_exact(
            VerifierBinding::new(
                TOOL_VERIFIER,
                VerifierGeneration::new(1).unwrap(),
                TOOL_COMMIT_RECEIPT_SCHEMA,
                Digest::new([0x77; 32]),
            )
            .unwrap(),
        )
    }

    fn verify(
        &self,
        challenge: &cser_core::EffectFactChallenge,
        _receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, cser_core::VerificationError> {
        Ok(VerifiedEffectObservation::commit(
            challenge.current_observation(),
            ExternalOutcome::Success,
            Digest::new([0xa6; 32]),
        ))
    }
}

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

fn coordinate(world: u64, provider: u64, generation: u64) -> ProviderCoordinate {
    ProviderCoordinate::new(
        WorldId::new(world).unwrap(),
        ProviderId::new(provider).unwrap(),
        ProviderGeneration::new(generation).unwrap(),
    )
}

fn verifiers_for(catalog: &DomainCatalog, implementation: u8) -> Vec<VerifierBinding> {
    catalog
        .verifier_class_bindings()
        .into_iter()
        .enumerate()
        .map(|(index, class)| {
            VerifierBinding::new(
                class.verifier(),
                VerifierGeneration::new(1).unwrap(),
                class.receipt_schema(),
                Digest::new([implementation.wrapping_add(index as u8); 32]),
            )
            .unwrap()
        })
        .collect()
}

fn tx(engine: &mut Engine, request: CommandRequest) -> Result<(), CoreError> {
    engine.transact_volatile(request).map(|_| ())
}

#[test]
fn provider_generation_high_water_is_monotonic_and_scoped() {
    let world = WorldId::new(7).unwrap();
    let mut engine = Engine::new(
        world,
        standard_catalog(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let digest = engine.catalog_digest();
    let first = coordinate(7, 11, 1);
    tx(
        &mut engine,
        CommandRequest::RegisterProviderGeneration {
            coordinate: first,
            catalog_digest: digest,
            verifier_bindings: verifiers_for(&standard_catalog(), 9),
        },
    )
    .unwrap();
    assert_eq!(engine.world(), Some(world));
    assert_eq!(
        engine.provider_generation_projection(first).unwrap().state,
        ProviderEffectState::Active
    );
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::RegisterProviderGeneration {
                coordinate: coordinate(7, 11, 1),
                catalog_digest: digest,
                verifier_bindings: verifiers_for(&standard_catalog(), 9),
            },
        ),
        Err(CoreError::ProviderGenerationStale)
    );
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::RegisterProviderGeneration {
                coordinate: coordinate(8, 11, 2),
                catalog_digest: digest,
                verifier_bindings: verifiers_for(&standard_catalog(), 9),
            },
        ),
        Err(CoreError::WorldMismatch)
    );
}

#[test]
fn provider_effect_lifecycle_is_ordered_and_retirement_is_exact() {
    let mut engine = Engine::new(
        WorldId::new(7).unwrap(),
        standard_catalog(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let provider = coordinate(7, 12, 1);
    let digest = engine.catalog_digest();
    tx(
        &mut engine,
        CommandRequest::RegisterProviderGeneration {
            coordinate: provider,
            catalog_digest: digest,
            verifier_bindings: verifiers_for(&standard_catalog(), 3),
        },
    )
    .unwrap();
    tx(
        &mut engine,
        CommandRequest::FenceProviderEffects {
            coordinate: provider,
            expected_epoch: 1,
        },
    )
    .unwrap();
    assert!(matches!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .state,
        ProviderEffectState::EffectFenced { .. }
    ));
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
        ProviderEffectState::Retired { .. }
    ));
}

#[test]
fn fenced_precommit_effect_can_abort_before_settlement_only() {
    let world = WorldId::new(71).unwrap();
    let mut engine = Engine::new(
        world,
        standard_catalog(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let provider = coordinate(71, 72, 1);
    let digest = engine.catalog_digest();
    tx(
        &mut engine,
        CommandRequest::RegisterProviderGeneration {
            coordinate: provider,
            catalog_digest: digest,
            verifier_bindings: verifiers_for(&standard_catalog(), 0x71),
        },
    )
    .unwrap();
    let effect = EffectId::new(RootId::new(7101).unwrap(), 1).unwrap();
    let actor = PrincipalIncarnation::new(PrincipalId::new(7101).unwrap(), 1).unwrap();
    tx(
        &mut engine,
        CommandRequest::AdmitScopedCompositeEffect {
            effect,
            operation: OperationId::new(7101).unwrap(),
            origin: actor,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: cser_core::ChargeAccountId::new(7101).unwrap(),
            bindings: vec![
                ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, provider),
                ComponentProviderBinding::new(AGENT_COMPONENT_DMA, provider),
            ],
        },
    )
    .unwrap();
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
    assert!(matches!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .state,
        ProviderEffectState::SettlementOnly { epoch: 3 }
    ));
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
        ProviderEffectState::Retired { epoch: 4 }
    ));
}

#[test]
fn scoped_engine_rejects_legacy_unbound_composite_constructor() {
    let world = WorldId::new(73).unwrap();
    let mut engine = Engine::new(
        world,
        standard_catalog(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let effect = EffectId::new(RootId::new(7301).unwrap(), 1).unwrap();
    let actor = PrincipalIncarnation::new(PrincipalId::new(7301).unwrap(), 1).unwrap();
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::CreateCompositeEffect {
                effect,
                origin: actor,
                binding_generation: 1,
                kind: AGENT_OPERATION_COMPOSITE,
                charge_account: cser_core::ChargeAccountId::new(7301).unwrap(),
            },
        ),
        Err(CoreError::IncompatibleApiProfile)
    );
}

#[test]
fn handoff_source_release_removes_scoped_binding_at_the_pivot() {
    let world = WorldId::new(74).unwrap();
    let mut engine = Engine::new(
        world,
        tool_dma_catalog(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let provider = coordinate(74, 75, 1);
    let digest = engine.catalog_digest();
    tx(
        &mut engine,
        CommandRequest::RegisterProviderGeneration {
            coordinate: provider,
            catalog_digest: digest,
            verifier_bindings: verifiers_for(&tool_dma_catalog(), 0x74),
        },
    )
    .unwrap();
    let parent = EffectId::new(RootId::new(7401).unwrap(), 1).unwrap();
    let actor = PrincipalIncarnation::new(PrincipalId::new(7401).unwrap(), 1).unwrap();
    tx(
        &mut engine,
        CommandRequest::AdmitScopedCompositeEffect {
            effect: parent,
            operation: OperationId::new(7401).unwrap(),
            origin: actor,
            binding_generation: 1,
            kind: TOOL_HANDOFF_SOURCE_COMPOSITE,
            charge_account: cser_core::ChargeAccountId::new(7401).unwrap(),
            bindings: vec![ComponentProviderBinding::new(
                TOOL_HANDOFF_SOURCE_COMPONENT,
                provider,
            )],
        },
    )
    .unwrap();
    tx(
        &mut engine,
        CommandRequest::AddComponentClaim {
            effect: parent,
            component: TOOL_HANDOFF_SOURCE_COMPONENT,
            actor,
            binding_generation: 1,
            claim: ClaimId::new(7401).unwrap(),
            kind: TOOL_CLAIM_OUTCOME_SLOT,
            scope: ClaimScope::Logical,
            resource: ResourceId::new(7401).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        },
    )
    .unwrap();
    tx(
        &mut engine,
        CommandRequest::PrepareCompositeEffect {
            effect: parent,
            actor,
            binding_generation: 1,
        },
    )
    .unwrap();
    let receipt = engine
        .transact_volatile(CommandRequest::RecordComponentCommitIntent {
            effect: parent,
            component: TOOL_HANDOFF_SOURCE_COMPONENT,
            actor,
            binding_generation: 1,
            operation: Digest::new([0x75; 32]),
        })
        .unwrap();
    let TransitionOutput::CommitIntent(intent) = receipt.into_output() else {
        panic!("expected source commit intent");
    };
    let descriptor = ChildDescriptorV1 {
        schema: 1,
        sequence: 1,
        parent,
        parent_component: TOOL_HANDOFF_SOURCE_COMPONENT,
        route_digest: Digest::new([0x76; 32]),
        child_kind: TOOL_HANDOFF_CHILD_COMPOSITE,
        child_component: TOOL_HANDOFF_COMPONENT,
        claim: ClaimId::new(7401).unwrap(),
        claim_kind: TOOL_CLAIM_OUTCOME_SLOT,
        scope: ClaimScope::Logical,
        resource: ResourceId::new(7401).unwrap(),
        resource_generation: ResourceGeneration::new(1).unwrap(),
        units: 1,
        input_digest: Digest::new([0x77; 32]),
        catalog_digest: digest,
    };
    let verified_descriptor = engine
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    let verified_outcome = engine
        .verify_commit_outcome(&intent, &AcceptEffect, &())
        .unwrap();
    engine
        .transact_volatile(
            intent
                .acknowledge_handoff_parent_success(verified_outcome, verified_descriptor)
                .unwrap(),
        )
        .unwrap();
    let verified = engine
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    engine
        .transact_volatile(verified.install(
            actor,
            1,
            cser_core::ChargeAccountId::new(7401).unwrap(),
        ))
        .unwrap();
    let verified = engine
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    engine
        .transact_volatile(verified.release_source_and_record_target_intent(
            actor,
            1,
            Digest::new([0x78; 32]),
        ))
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
        CommandRequest::FenceProviderEffects {
            coordinate: provider,
            expected_epoch: 1,
        },
    )
    .unwrap();
    tx(
        &mut engine,
        CommandRequest::EnterProviderSettlementOnly {
            coordinate: provider,
            expected_epoch: 2,
        },
    )
    .unwrap();
}

#[test]
fn scoped_admission_binds_exact_operation_and_components() {
    let world = WorldId::new(9).unwrap();
    let mut engine = Engine::new(
        world,
        standard_catalog(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let reply = coordinate(9, 21, 1);
    let dma = coordinate(9, 22, 1);
    let digest = engine.catalog_digest();
    for provider in [reply, dma] {
        tx(
            &mut engine,
            CommandRequest::RegisterProviderGeneration {
                coordinate: provider,
                catalog_digest: digest,
                verifier_bindings: verifiers_for(&standard_catalog(), 4),
            },
        )
        .unwrap();
    }
    let effect = EffectId::new(RootId::new(91).unwrap(), 1).unwrap();
    let actor = PrincipalIncarnation::new(PrincipalId::new(91).unwrap(), 1).unwrap();
    tx(
        &mut engine,
        CommandRequest::AdmitScopedCompositeEffect {
            effect,
            operation: OperationId::new(1).unwrap(),
            origin: actor,
            binding_generation: 1,
            kind: cser_core::AGENT_OPERATION_COMPOSITE,
            charge_account: cser_core::ChargeAccountId::new(91).unwrap(),
            bindings: vec![
                ComponentProviderBinding::new(cser_core::AGENT_COMPONENT_REPLY, reply),
                ComponentProviderBinding::new(cser_core::AGENT_COMPONENT_DMA, dma),
            ],
        },
    )
    .unwrap();
    let projection = engine.composite_effect(effect).unwrap();
    assert_eq!(projection.operation, Some(OperationId::new(1).unwrap()));
    assert_eq!(projection.provider_bindings.len(), 2);
    assert_eq!(
        engine
            .provider_generation_projection(reply)
            .unwrap()
            .live_component_bindings,
        1
    );
    assert_eq!(
        engine
            .provider_generation_projection(dma)
            .unwrap()
            .live_component_bindings,
        1
    );
}
