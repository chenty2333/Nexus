use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration,
    CatalogSet, ChildDescriptorV1, ChildDescriptorVerifier, ClaimId, ClaimScope, CommandRequest,
    ComponentProviderBinding, CoreError, CoreLimits, DeviceGeneration, Digest, DomainCatalog,
    EffectFactChallenge, EffectFactKind, EffectId, EffectReceiptVerifier, Engine,
    ExecutorCoordinate, ExecutorGeneration, ExecutorId, ExternalOutcome, Freshness,
    JournalGeneration, OperationId, ProviderCoordinate, ProviderEffectState, ProviderGeneration,
    ProviderId, ReceiptVerifier, RecoveryAnchor, RecoveryBinding, RecoveryProfile,
    RegistryInstance, ResourceGeneration, ResourceId, SingleHopHandoffProjection,
    TOOL_APPLY_RECEIPT_SCHEMA, TOOL_CLAIM_OUTCOME_SLOT, TOOL_COMMIT_RECEIPT_SCHEMA,
    TOOL_EVIDENCE_OUTCOME_ACK, TOOL_HANDOFF_CHILD_COMPOSITE, TOOL_HANDOFF_COMPONENT,
    TOOL_HANDOFF_SOURCE_COMPONENT, TOOL_HANDOFF_SOURCE_COMPOSITE, TOOL_RECEIPT_SCHEMA,
    TOOL_SETTLEMENT_RECEIPT_SCHEMA, TOOL_VERIFIER, TransitionEvent, TransitionOutput,
    VerifiedEffectObservation, VerifiedObservation, VerifierBinding, VerifierGeneration,
    VerifierIdentity, WorldId, standard_catalog, tool_dma_catalog,
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

#[derive(Clone, Copy)]
struct AcceptHandoffChildRecovery {
    identity: VerifierIdentity,
}

impl cser_core::HandoffChildResolutionVerifier for AcceptHandoffChildRecovery {
    type Receipt = ();

    fn identity(&self) -> VerifierIdentity {
        self.identity
    }

    fn verify_handoff_child_success(
        &self,
        _challenge: &cser_core::HandoffResolutionChallenge,
        _receipt: &Self::Receipt,
    ) -> Result<Digest, cser_core::VerificationError> {
        Ok(Digest::new([0xa7; 32]))
    }
}

#[derive(Clone, Copy)]
struct ScopedEffectVerifier {
    identity: VerifierIdentity,
}

impl EffectReceiptVerifier for ScopedEffectVerifier {
    type Receipt = ();

    fn identity(&self) -> VerifierIdentity {
        self.identity
    }

    fn verify(
        &self,
        challenge: &EffectFactChallenge,
        _receipt: &Self::Receipt,
    ) -> Result<VerifiedEffectObservation, cser_core::VerificationError> {
        let digest = Digest::new([challenge.kind() as u8 + 0x80; 32]);
        Ok(match challenge.kind() {
            EffectFactKind::CommitOutcome => VerifiedEffectObservation::commit(
                challenge.current_observation(),
                ExternalOutcome::Success,
                digest,
            ),
            EffectFactKind::ApplyCompleted | EffectFactKind::SettlementAcknowledged => {
                VerifiedEffectObservation::fact(challenge.current_observation(), digest)
            }
        })
    }
}

#[derive(Clone, Copy)]
struct ScopedEvidenceVerifier {
    identity: VerifierIdentity,
}

impl ReceiptVerifier for ScopedEvidenceVerifier {
    type Receipt = ();

    fn identity(&self) -> VerifierIdentity {
        self.identity
    }

    fn verify(
        &self,
        challenge: &cser_core::EvidenceChallenge,
        _receipt: &Self::Receipt,
    ) -> Result<VerifiedObservation, cser_core::VerificationError> {
        Ok(VerifiedObservation::new_bound(
            challenge.subject(),
            challenge.subject_binding(),
            challenge.current_observation(),
            challenge.current_binding(),
            Digest::new([0xb7; 32]),
        ))
    }
}

fn scoped_identity(
    catalog: &DomainCatalog,
    verifier: cser_core::VerifierId,
    schema: cser_core::ReceiptSchemaId,
    implementation: u8,
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
            Digest::new([implementation.wrapping_add(index as u8); 32]),
        )
        .unwrap(),
    )
}

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
    current: Freshness,
) -> RecoveryBinding {
    RecoveryBinding::new(
        RecoveryProfile::current(),
        world,
        CatalogSet::new(std::slice::from_ref(catalog))
            .unwrap()
            .digest(),
        current.registry(),
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

fn tx<C: Into<cser_core::Command>>(engine: &mut Engine, request: C) -> Result<(), CoreError> {
    engine.transact_volatile(request).map(|_| ())
}

fn durable_output<C: Into<cser_core::Command>>(
    engine: &mut Engine,
    journal: &mut Vec<u8>,
    request: C,
) -> TransitionOutput {
    engine
        .transact(request, |record| {
            journal.extend_from_slice(record.bytes());
            Ok::<(), ()>(())
        })
        .unwrap()
        .into_output()
}

struct TerminalHandoffFixture {
    engine: Engine,
    catalog: DomainCatalog,
    journal: Vec<u8>,
    world: WorldId,
    provider: ProviderCoordinate,
    target_provider: ProviderCoordinate,
    parent: EffectId,
    actor: ExecutorCoordinate,
    descriptor: ChildDescriptorV1,
}

fn terminal_handoff_fixture(
    world_number: u64,
    operation_number: u64,
    provider_number: u64,
    target_provider_number: u64,
) -> TerminalHandoffFixture {
    let world = WorldId::new(world_number).unwrap();
    let catalog = tool_dma_catalog();
    let mut engine = Engine::new(
        world,
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::new(64, 1024, 4096, 4096, 32, 1, 1024).unwrap(),
        freshness(),
    );
    let mut journal = Vec::new();
    let provider = coordinate(world_number, provider_number, 1);
    let target_provider = coordinate(world_number, target_provider_number, 1);
    let digest = catalog.digest();
    durable_output(
        &mut engine,
        &mut journal,
        CommandRequest::RegisterProviderGeneration {
            coordinate: provider,
            catalog_digest: digest,
            verifier_bindings: verifiers_for(&catalog, 0x74),
        },
    );
    durable_output(
        &mut engine,
        &mut journal,
        CommandRequest::RegisterProviderGeneration {
            coordinate: target_provider,
            catalog_digest: digest,
            verifier_bindings: verifiers_for(&catalog, 0x75),
        },
    );
    let parent = EffectId::new(OperationId::new(operation_number).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(operation_number).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    let claim = ClaimId::new(operation_number).unwrap();
    let resource = ResourceId::new(operation_number).unwrap();
    durable_output(
        &mut engine,
        &mut journal,
        CommandRequest::AdmitScopedCompositeEffect {
            effect: parent,
            origin: actor,
            kind: TOOL_HANDOFF_SOURCE_COMPOSITE,
            charge_account: cser_core::ChargeAccountId::new(operation_number).unwrap(),
            bindings: vec![ComponentProviderBinding::new(
                TOOL_HANDOFF_SOURCE_COMPONENT,
                provider,
            )],
        },
    );
    durable_output(
        &mut engine,
        &mut journal,
        CommandRequest::AddComponentClaim {
            effect: parent,
            component: TOOL_HANDOFF_SOURCE_COMPONENT,
            actor,
            claim,
            kind: TOOL_CLAIM_OUTCOME_SLOT,
            scope: ClaimScope::Logical,
            resource,
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        },
    );
    durable_output(
        &mut engine,
        &mut journal,
        CommandRequest::PrepareCompositeEffect {
            effect: parent,
            actor,
        },
    );
    let intent = match durable_output(
        &mut engine,
        &mut journal,
        CommandRequest::RecordComponentCommitIntent {
            effect: parent,
            component: TOOL_HANDOFF_SOURCE_COMPONENT,
            actor,
            operation: Digest::new([0x75; 32]),
        },
    ) {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected source commit intent, got {other:?}"),
    };
    let descriptor = ChildDescriptorV1 {
        schema: 1,
        sequence: 1,
        parent,
        parent_component: TOOL_HANDOFF_SOURCE_COMPONENT,
        route_digest: Digest::new([0x76; 32]),
        child_kind: TOOL_HANDOFF_CHILD_COMPOSITE,
        child_component: TOOL_HANDOFF_COMPONENT,
        claim,
        claim_kind: TOOL_CLAIM_OUTCOME_SLOT,
        scope: ClaimScope::Logical,
        resource,
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
    durable_output(
        &mut engine,
        &mut journal,
        intent
            .acknowledge_handoff_parent_success(verified_outcome, verified_descriptor)
            .unwrap(),
    );
    TerminalHandoffFixture {
        engine,
        catalog,
        journal,
        world,
        provider,
        target_provider,
        parent,
        actor,
        descriptor,
    }
}

fn settle_terminal_handoff_source(fixture: &mut TerminalHandoffFixture) {
    let settlement = match durable_output(
        &mut fixture.engine,
        &mut fixture.journal,
        CommandRequest::ClaimComponentSettlement {
            effect: fixture.parent,
            component: TOOL_HANDOFF_SOURCE_COMPONENT,
            claimant: fixture.actor,
        },
    ) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected source settlement claim, got {other:?}"),
    };
    let settlement = match durable_output(
        &mut fixture.engine,
        &mut fixture.journal,
        settlement
            .record_apply_intent(Digest::new([0x79; 32]))
            .unwrap(),
    ) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected source apply-intent claim, got {other:?}"),
    };
    let applied = fixture
        .engine
        .verify_apply_completion(
            &settlement,
            &ScopedEffectVerifier {
                identity: scoped_identity(
                    &fixture.catalog,
                    TOOL_VERIFIER,
                    TOOL_APPLY_RECEIPT_SCHEMA,
                    0x74,
                ),
            },
            &(),
        )
        .unwrap();
    let settlement = match durable_output(
        &mut fixture.engine,
        &mut fixture.journal,
        settlement.record_applied(applied).unwrap(),
    ) {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected source applied claim, got {other:?}"),
    };
    let acknowledgement = fixture
        .engine
        .verify_settlement_ack(
            &settlement,
            &ScopedEffectVerifier {
                identity: scoped_identity(
                    &fixture.catalog,
                    TOOL_VERIFIER,
                    TOOL_SETTLEMENT_RECEIPT_SCHEMA,
                    0x74,
                ),
            },
            &(),
        )
        .unwrap();
    durable_output(
        &mut fixture.engine,
        &mut fixture.journal,
        settlement.settle(acknowledgement).unwrap(),
    );
    let evidence = fixture
        .engine
        .verify_component_retirement_evidence(
            fixture.parent,
            TOOL_HANDOFF_SOURCE_COMPONENT,
            fixture.descriptor.claim,
            TOOL_EVIDENCE_OUTCOME_ACK,
            &ScopedEvidenceVerifier {
                identity: scoped_identity(
                    &fixture.catalog,
                    TOOL_VERIFIER,
                    TOOL_RECEIPT_SCHEMA,
                    0x74,
                ),
            },
            &(),
        )
        .unwrap();
    durable_output(&mut fixture.engine, &mut fixture.journal, evidence.submit());
}

#[test]
fn provider_generation_high_water_is_monotonic_and_scoped() {
    let world = WorldId::new(7).unwrap();
    let mut engine = Engine::new(
        world,
        CatalogSet::new(&[standard_catalog()]).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let digest = standard_catalog().digest();
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
    assert_eq!(engine.world(), world);
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
        CatalogSet::new(&[standard_catalog()]).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let provider = coordinate(7, 12, 1);
    let digest = standard_catalog().digest();
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
        CatalogSet::new(&[standard_catalog()]).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let provider = coordinate(71, 72, 1);
    let digest = standard_catalog().digest();
    tx(
        &mut engine,
        CommandRequest::RegisterProviderGeneration {
            coordinate: provider,
            catalog_digest: digest,
            verifier_bindings: verifiers_for(&standard_catalog(), 0x71),
        },
    )
    .unwrap();
    let effect = EffectId::new(OperationId::new(7101).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(7101).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    tx(
        &mut engine,
        CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin: actor,
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
fn handoff_source_release_removes_scoped_binding_at_the_pivot() {
    let world = WorldId::new(74).unwrap();
    let catalog = tool_dma_catalog();
    let mut engine = Engine::new(
        world,
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::new(64, 1024, 4096, 4096, 32, 1, 1024).unwrap(),
        freshness(),
    );
    let mut journal = Vec::new();
    macro_rules! durable {
        ($request:expr $(,)?) => {
            engine
                .transact($request, |record| {
                    journal.extend_from_slice(record.bytes());
                    Ok::<(), ()>(())
                })
                .unwrap()
        };
    }
    let provider = coordinate(74, 75, 1);
    let target_provider = coordinate(74, 76, 1);
    let digest = catalog.digest();
    durable!(CommandRequest::RegisterProviderGeneration {
        coordinate: provider,
        catalog_digest: digest,
        verifier_bindings: verifiers_for(&catalog, 0x74),
    });
    durable!(CommandRequest::RegisterProviderGeneration {
        coordinate: target_provider,
        catalog_digest: digest,
        verifier_bindings: verifiers_for(&catalog, 0x75),
    });
    let parent = EffectId::new(OperationId::new(7401).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(7401).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    durable!(CommandRequest::AdmitScopedCompositeEffect {
        effect: parent,
        origin: actor,
        kind: TOOL_HANDOFF_SOURCE_COMPOSITE,
        charge_account: cser_core::ChargeAccountId::new(7401).unwrap(),
        bindings: vec![ComponentProviderBinding::new(
            TOOL_HANDOFF_SOURCE_COMPONENT,
            provider,
        )],
    });
    durable!(CommandRequest::AddComponentClaim {
        effect: parent,
        component: TOOL_HANDOFF_SOURCE_COMPONENT,
        actor,
        claim: ClaimId::new(7401).unwrap(),
        kind: TOOL_CLAIM_OUTCOME_SLOT,
        scope: ClaimScope::Logical,
        resource: ResourceId::new(7401).unwrap(),
        resource_generation: ResourceGeneration::new(1).unwrap(),
        units: 1,
    });
    durable!(CommandRequest::PrepareCompositeEffect {
        effect: parent,
        actor,
    });
    let receipt = durable!(CommandRequest::RecordComponentCommitIntent {
        effect: parent,
        component: TOOL_HANDOFF_SOURCE_COMPONENT,
        actor,
        operation: Digest::new([0x75; 32]),
    });
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
    durable!(
        intent
            .acknowledge_handoff_parent_success(verified_outcome, verified_descriptor)
            .unwrap()
    );
    let child = descriptor.child_effect().unwrap();
    let verified = engine
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    durable!(verified.install(
        actor,
        // At an exact account ceiling, the inactive child must not be
        // transiently double-charged during install or pivot.
        cser_core::ChargeAccountId::new(7401).unwrap(),
        ComponentProviderBinding::new(TOOL_HANDOFF_COMPONENT, target_provider),
    ));

    // A prepared child never turns a still-open source into a legal pivot.
    let verified = engine
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    assert_eq!(
        engine.transact_volatile(
            verified.release_source_and_record_target_intent(actor, Digest::new([0x78; 32]))
        ),
        Err(CoreError::HandoffGuardRequired)
    );

    // Match the OSTD lifecycle: ordinary successor settlement and typed
    // retirement release the source accounting before the custody pivot.
    let settlement = match durable!(CommandRequest::ClaimComponentSettlement {
        effect: parent,
        component: TOOL_HANDOFF_SOURCE_COMPONENT,
        claimant: actor,
    })
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected source settlement claim, got {other:?}"),
    };
    let settlement = match durable!(
        settlement
            .record_apply_intent(Digest::new([0x79; 32]))
            .unwrap()
    )
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected source apply-intent claim, got {other:?}"),
    };
    let applied = engine
        .verify_apply_completion(
            &settlement,
            &ScopedEffectVerifier {
                identity: scoped_identity(&catalog, TOOL_VERIFIER, TOOL_APPLY_RECEIPT_SCHEMA, 0x74),
            },
            &(),
        )
        .unwrap();
    let settlement = match durable!(settlement.record_applied(applied).unwrap()).into_output() {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected source applied claim, got {other:?}"),
    };
    let acknowledgement = engine
        .verify_settlement_ack(
            &settlement,
            &ScopedEffectVerifier {
                identity: scoped_identity(
                    &catalog,
                    TOOL_VERIFIER,
                    TOOL_SETTLEMENT_RECEIPT_SCHEMA,
                    0x74,
                ),
            },
            &(),
        )
        .unwrap();
    durable!(settlement.settle(acknowledgement).unwrap());

    // Settlement alone is insufficient while the source claim still awaits
    // typed retirement evidence.
    let verified = engine
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    assert_eq!(
        engine.transact_volatile(
            verified.release_source_and_record_target_intent(actor, Digest::new([0x7a; 32]))
        ),
        Err(CoreError::HandoffGuardRequired)
    );

    let evidence = engine
        .verify_component_retirement_evidence(
            parent,
            TOOL_HANDOFF_SOURCE_COMPONENT,
            ClaimId::new(7401).unwrap(),
            TOOL_EVIDENCE_OUTCOME_ACK,
            &ScopedEvidenceVerifier {
                identity: scoped_identity(&catalog, TOOL_VERIFIER, TOOL_RECEIPT_SCHEMA, 0x74),
            },
            &(),
        )
        .unwrap();
    durable!(evidence.submit());
    assert_eq!(
        engine
            .component(parent, TOOL_HANDOFF_SOURCE_COMPONENT)
            .unwrap()
            .retirement,
        cser_core::RetirementState::Retired
    );

    // Ordinary source retirement leaves this exact generation absent from the
    // live index and charge aggregate, but the accepted source descriptor
    // still reserves it until the child pivot or an explicit abort.  Both the
    // read-only reusable check and the durable reuse command must observe that
    // reservation instead of advancing the generation behind the descriptor.
    assert_eq!(
        engine.check_reusable(descriptor.resource, descriptor.resource_generation,),
        Err(CoreError::ResourceRetained)
    );
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::ReserveComponentReuse {
                effect: child,
                component: TOOL_HANDOFF_COMPONENT,
                actor,
                claim: ClaimId::new(7402).unwrap(),
                kind: TOOL_CLAIM_OUTCOME_SLOT,
                scope: ClaimScope::Logical,
                resource: descriptor.resource,
                expected_generation: descriptor.resource_generation,
                units: descriptor.units,
                reuse_contract: Digest::new([0x7b; 32]),
            },
        ),
        Err(CoreError::ResourceRetained)
    );

    // The reservation is derived from the durable source role, so a cold
    // replay followed by checkpoint recovery must retain the same exclusion.
    let recovery_freshness = Freshness::new(
        BootGeneration::new(2).unwrap(),
        RegistryInstance::new(1).unwrap(),
        DeviceGeneration::new(1).unwrap(),
        JournalGeneration::new(2).unwrap(),
    );
    let mut recovered_before_pivot = Engine::recover(
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            recovery_binding(world, &catalog, freshness()),
            freshness(),
            recovery_freshness,
            engine.revision(),
            engine.head(),
            engine.projection_digest(),
        )
        .unwrap(),
        &journal,
    )
    .unwrap()
    .into_engine();
    recovered_before_pivot
        .transact_volatile(CommandRequest::CheckpointRecovery {
            boot: recovery_freshness.boot(),
            journal: recovery_freshness.journal(),
            device: recovery_freshness.device(),
        })
        .unwrap();
    assert_eq!(
        recovered_before_pivot.check_reusable(descriptor.resource, descriptor.resource_generation,),
        Err(CoreError::ResourceRetained)
    );

    let verified = engine
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    durable!(verified.release_source_and_record_target_intent(actor, Digest::new([0x78; 32])));
    assert_eq!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .live_component_bindings,
        0
    );
    assert_eq!(
        engine
            .provider_generation_projection(target_provider)
            .unwrap()
            .live_component_bindings,
        1
    );

    // The pivot has released the parent provider binding into immutable
    // provenance. A cold recovery must still select the installed child
    // branch after its consumed intent becomes indeterminate.
    let next_freshness = Freshness::new(
        BootGeneration::new(2).unwrap(),
        RegistryInstance::new(1).unwrap(),
        DeviceGeneration::new(1).unwrap(),
        JournalGeneration::new(2).unwrap(),
    );
    let mut recovered_journal = journal.clone();
    let mut recovered = Engine::recover(
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            recovery_binding(world, &catalog, freshness()),
            freshness(),
            next_freshness,
            engine.revision(),
            engine.head(),
            engine.projection_digest(),
        )
        .unwrap(),
        &recovered_journal,
    )
    .unwrap()
    .into_engine();
    durable_output(
        &mut recovered,
        &mut recovered_journal,
        CommandRequest::CheckpointRecovery {
            boot: next_freshness.boot(),
            journal: next_freshness.journal(),
            device: next_freshness.device(),
        },
    );
    let verified = recovered
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    let stale_resolution = recovered
        .verify_handoff_child_resolution(
            verified,
            &AcceptHandoffChildRecovery {
                identity: scoped_identity(
                    &catalog,
                    TOOL_VERIFIER,
                    TOOL_COMMIT_RECEIPT_SCHEMA,
                    0x75,
                ),
            },
            &(),
        )
        .unwrap();
    let later_freshness = Freshness::new(
        BootGeneration::new(3).unwrap(),
        RegistryInstance::new(1).unwrap(),
        DeviceGeneration::new(1).unwrap(),
        JournalGeneration::new(3).unwrap(),
    );
    let mut stale_journal = recovered_journal.clone();
    let mut advanced = Engine::recover(
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            recovery_binding(world, &catalog, next_freshness),
            next_freshness,
            later_freshness,
            recovered.revision(),
            recovered.head(),
            recovered.projection_digest(),
        )
        .unwrap(),
        &stale_journal,
    )
    .unwrap()
    .into_engine();
    durable_output(
        &mut advanced,
        &mut stale_journal,
        CommandRequest::CheckpointRecovery {
            boot: later_freshness.boot(),
            journal: later_freshness.journal(),
            device: later_freshness.device(),
        },
    );
    let revision_after_checkpoint = advanced.revision();
    let head_after_checkpoint = advanced.head();
    let projection_after_checkpoint = advanced.projection_digest();
    let outcome_after_checkpoint = advanced
        .component(child, TOOL_HANDOFF_COMPONENT)
        .unwrap()
        .outcome;
    assert_eq!(
        advanced.transact_volatile(stale_resolution.resolve()),
        Err(CoreError::HandoffGuardRequired)
    );
    assert_eq!(advanced.revision(), revision_after_checkpoint);
    assert_eq!(advanced.head(), head_after_checkpoint);
    assert_eq!(advanced.projection_digest(), projection_after_checkpoint);
    assert_eq!(
        advanced
            .component(child, TOOL_HANDOFF_COMPONENT)
            .unwrap()
            .outcome,
        outcome_after_checkpoint
    );
    let verified = recovered
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    let resolution = recovered
        .verify_handoff_child_resolution(
            verified,
            &AcceptHandoffChildRecovery {
                identity: scoped_identity(
                    &catalog,
                    TOOL_VERIFIER,
                    TOOL_COMMIT_RECEIPT_SCHEMA,
                    0x75,
                ),
            },
            &(),
        )
        .unwrap();
    durable_output(&mut recovered, &mut recovered_journal, resolution.resolve());
    assert_eq!(
        recovered
            .component(child, TOOL_HANDOFF_COMPONENT)
            .unwrap()
            .outcome,
        cser_core::OutcomeState::KnownSuccess(Digest::new([0xa7; 32]))
    );

    // The accepted child fact is historical verification provenance. A
    // second production-shaped cold recovery must keep it valid when the
    // checkpoint advances from N to N+1, while the full invariant oracle
    // audits the hot transition and checkpoint replay.
    let mut recovered_again = Engine::recover(
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            recovery_binding(world, &catalog, next_freshness),
            next_freshness,
            later_freshness,
            recovered.revision(),
            recovered.head(),
            recovered.projection_digest(),
        )
        .unwrap(),
        &recovered_journal,
    )
    .unwrap()
    .into_engine();
    durable_output(
        &mut recovered_again,
        &mut recovered_journal,
        CommandRequest::CheckpointRecovery {
            boot: later_freshness.boot(),
            journal: later_freshness.journal(),
            device: later_freshness.device(),
        },
    );
    recovered_again
        .journal_checkpoint(&recovered_journal)
        .unwrap();

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
fn terminal_retired_handoff_reservation_survives_recovery_before_child_install() {
    let mut fixture = terminal_handoff_fixture(742, 7421, 7422, 7423);
    settle_terminal_handoff_source(&mut fixture);
    let descriptor = fixture.descriptor;
    let child = descriptor.child_effect().unwrap();

    assert_eq!(
        fixture
            .engine
            .check_reusable(descriptor.resource, descriptor.resource_generation),
        Err(CoreError::ResourceRetained)
    );
    assert_eq!(
        tx(
            &mut fixture.engine,
            CommandRequest::ReserveComponentReuse {
                effect: fixture.parent,
                component: TOOL_HANDOFF_SOURCE_COMPONENT,
                actor: fixture.actor,
                claim: ClaimId::new(7422).unwrap(),
                kind: TOOL_CLAIM_OUTCOME_SLOT,
                scope: ClaimScope::Logical,
                resource: descriptor.resource,
                expected_generation: descriptor.resource_generation,
                units: descriptor.units,
                reuse_contract: Digest::new([0x7b; 32]),
            },
        ),
        Err(CoreError::ResourceRetained)
    );

    let next_freshness = Freshness::new(
        BootGeneration::new(2).unwrap(),
        RegistryInstance::new(1).unwrap(),
        DeviceGeneration::new(1).unwrap(),
        JournalGeneration::new(2).unwrap(),
    );
    let mut recovered = Engine::recover(
        CatalogSet::new(std::slice::from_ref(&fixture.catalog)).unwrap(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            recovery_binding(fixture.world, &fixture.catalog, freshness()),
            freshness(),
            next_freshness,
            fixture.engine.revision(),
            fixture.engine.head(),
            fixture.engine.projection_digest(),
        )
        .unwrap(),
        &fixture.journal,
    )
    .unwrap()
    .into_engine();
    recovered
        .transact_volatile(CommandRequest::CheckpointRecovery {
            boot: next_freshness.boot(),
            journal: next_freshness.journal(),
            device: next_freshness.device(),
        })
        .unwrap();
    assert_eq!(
        recovered.check_reusable(descriptor.resource, descriptor.resource_generation),
        Err(CoreError::ResourceRetained)
    );

    let verified = fixture
        .engine
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    durable_output(
        &mut fixture.engine,
        &mut fixture.journal,
        verified.install(
            fixture.actor,
            cser_core::ChargeAccountId::new(7421).unwrap(),
            ComponentProviderBinding::new(TOOL_HANDOFF_COMPONENT, fixture.target_provider),
        ),
    );
    assert_eq!(
        fixture
            .engine
            .component(child, TOOL_HANDOFF_COMPONENT)
            .unwrap()
            .claim_count,
        1
    );

    let verified = fixture
        .engine
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    durable_output(
        &mut fixture.engine,
        &mut fixture.journal,
        verified.release_source_and_record_target_intent(fixture.actor, Digest::new([0x7c; 32])),
    );
    assert_eq!(
        fixture
            .engine
            .provider_generation_projection(fixture.provider)
            .unwrap()
            .live_component_bindings,
        0
    );
    assert_eq!(
        fixture
            .engine
            .provider_generation_projection(fixture.target_provider)
            .unwrap()
            .live_component_bindings,
        1
    );
    assert_eq!(
        fixture
            .engine
            .component(child, TOOL_HANDOFF_COMPONENT)
            .unwrap()
            .claim_count,
        1
    );
}

#[test]
fn terminal_retired_handoff_abort_releases_resource_reservation() {
    let mut fixture = terminal_handoff_fixture(743, 7431, 7432, 7433);
    settle_terminal_handoff_source(&mut fixture);
    let descriptor = fixture.descriptor;
    let child = descriptor.child_effect().unwrap();
    let verified = fixture
        .engine
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    durable_output(
        &mut fixture.engine,
        &mut fixture.journal,
        verified.install(
            fixture.actor,
            cser_core::ChargeAccountId::new(7431).unwrap(),
            ComponentProviderBinding::new(TOOL_HANDOFF_COMPONENT, fixture.target_provider),
        ),
    );
    assert_eq!(
        fixture
            .engine
            .check_reusable(descriptor.resource, descriptor.resource_generation),
        Err(CoreError::ResourceRetained)
    );
    durable_output(
        &mut fixture.engine,
        &mut fixture.journal,
        CommandRequest::FenceProviderEffects {
            coordinate: fixture.target_provider,
            expected_epoch: 1,
        },
    );
    durable_output(
        &mut fixture.engine,
        &mut fixture.journal,
        CommandRequest::AbortUnescapedEffect { effect: child },
    );
    assert_eq!(
        fixture
            .engine
            .composite_effect(fixture.parent)
            .unwrap()
            .handoff,
        SingleHopHandoffProjection::None
    );
    assert_eq!(
        fixture
            .engine
            .check_reusable(descriptor.resource, descriptor.resource_generation),
        Ok(())
    );
    assert_eq!(
        fixture
            .engine
            .component(child, TOOL_HANDOFF_COMPONENT)
            .unwrap()
            .claim_count,
        0
    );
}

#[test]
fn fenced_prepared_handoff_child_aborts_and_recovers_as_released() {
    let world = WorldId::new(741).unwrap();
    let catalog = tool_dma_catalog();
    let mut engine = Engine::new(
        world,
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let mut journal = Vec::new();
    macro_rules! durable {
        ($request:expr $(,)?) => {
            engine
                .transact($request, |record| {
                    journal.extend_from_slice(record.bytes());
                    Ok::<(), ()>(())
                })
                .unwrap()
        };
    }
    let provider = coordinate(741, 742, 1);
    let target_provider = coordinate(741, 743, 1);
    let digest = catalog.digest();
    durable!(CommandRequest::RegisterProviderGeneration {
        coordinate: provider,
        catalog_digest: digest,
        verifier_bindings: verifiers_for(&catalog, 0x74),
    });
    durable!(CommandRequest::RegisterProviderGeneration {
        coordinate: target_provider,
        catalog_digest: digest,
        verifier_bindings: verifiers_for(&catalog, 0x75),
    });

    let parent = EffectId::new(OperationId::new(7411).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(7411).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    durable!(CommandRequest::AdmitScopedCompositeEffect {
        effect: parent,
        origin: actor,
        kind: TOOL_HANDOFF_SOURCE_COMPOSITE,
        charge_account: cser_core::ChargeAccountId::new(7411).unwrap(),
        bindings: vec![ComponentProviderBinding::new(
            TOOL_HANDOFF_SOURCE_COMPONENT,
            provider,
        )],
    });
    durable!(CommandRequest::AddComponentClaim {
        effect: parent,
        component: TOOL_HANDOFF_SOURCE_COMPONENT,
        actor,
        claim: ClaimId::new(7411).unwrap(),
        kind: TOOL_CLAIM_OUTCOME_SLOT,
        scope: ClaimScope::Logical,
        resource: ResourceId::new(7411).unwrap(),
        resource_generation: ResourceGeneration::new(1).unwrap(),
        units: 1,
    });
    durable!(CommandRequest::PrepareCompositeEffect {
        effect: parent,
        actor,
    });
    let receipt = durable!(CommandRequest::RecordComponentCommitIntent {
        effect: parent,
        component: TOOL_HANDOFF_SOURCE_COMPONENT,
        actor,
        operation: Digest::new([0x93; 32]),
    });
    let TransitionOutput::CommitIntent(intent) = receipt.into_output() else {
        panic!("expected source commit intent");
    };
    let descriptor = ChildDescriptorV1 {
        schema: 1,
        sequence: 1,
        parent,
        parent_component: TOOL_HANDOFF_SOURCE_COMPONENT,
        route_digest: Digest::new([0x94; 32]),
        child_kind: TOOL_HANDOFF_CHILD_COMPOSITE,
        child_component: TOOL_HANDOFF_COMPONENT,
        claim: ClaimId::new(7411).unwrap(),
        claim_kind: TOOL_CLAIM_OUTCOME_SLOT,
        scope: ClaimScope::Logical,
        resource: ResourceId::new(7411).unwrap(),
        resource_generation: ResourceGeneration::new(1).unwrap(),
        units: 1,
        input_digest: Digest::new([0x95; 32]),
        catalog_digest: digest,
    };
    let verified_descriptor = engine
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    let verified_outcome = engine
        .verify_commit_outcome(&intent, &AcceptEffect, &())
        .unwrap();
    durable!(
        intent
            .acknowledge_handoff_parent_success(verified_outcome, verified_descriptor)
            .unwrap()
    );
    let verified = engine
        .verify_child_descriptor(descriptor, &AcceptDescriptor, &())
        .unwrap();
    let child = descriptor.child_effect().unwrap();
    durable!(verified.install(
        actor,
        cser_core::ChargeAccountId::new(7411).unwrap(),
        ComponentProviderBinding::new(TOOL_HANDOFF_COMPONENT, target_provider),
    ));

    durable!(CommandRequest::FenceProviderEffects {
        coordinate: target_provider,
        expected_epoch: 1,
    });
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::EnterProviderSettlementOnly {
                coordinate: target_provider,
                expected_epoch: 2,
            },
        ),
        Err(CoreError::ProviderEffectsLive)
    );

    let receipt = durable!(CommandRequest::AbortUnescapedEffect { effect: child });
    assert_eq!(receipt.event(), TransitionEvent::CompositeEffectReleased);
    assert_eq!(
        engine.composite_effect(parent).unwrap().handoff,
        SingleHopHandoffProjection::None
    );
    assert_eq!(
        engine.composite_effect(child).unwrap().handoff,
        SingleHopHandoffProjection::None
    );
    assert_eq!(
        engine
            .component(child, TOOL_HANDOFF_COMPONENT)
            .unwrap()
            .claim_count,
        0
    );
    assert_eq!(
        engine
            .component(child, TOOL_HANDOFF_COMPONENT)
            .unwrap()
            .retirement,
        cser_core::RetirementState::Released
    );
    assert_eq!(
        engine
            .provider_generation_projection(target_provider)
            .unwrap()
            .live_component_bindings,
        0
    );
    durable!(CommandRequest::EnterProviderSettlementOnly {
        coordinate: target_provider,
        expected_epoch: 2,
    });
    durable!(CommandRequest::RetireProviderEffects {
        coordinate: target_provider,
        expected_epoch: 3,
    });

    let next_freshness = Freshness::new(
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
            next_freshness,
            engine.revision(),
            engine.head(),
            engine.projection_digest(),
        )
        .unwrap(),
        &journal,
    )
    .unwrap()
    .into_engine();
    assert_eq!(
        recovered.composite_effect(parent).unwrap().handoff,
        SingleHopHandoffProjection::None
    );
    assert_eq!(
        recovered
            .component(child, TOOL_HANDOFF_COMPONENT)
            .unwrap()
            .claim_count,
        0
    );
    assert!(matches!(
        recovered
            .provider_generation_projection(target_provider)
            .unwrap()
            .state,
        ProviderEffectState::Retired { .. }
    ));

    let checkpoint = engine.journal_checkpoint(&journal).unwrap();
    let checkpoint_recovered = Engine::recover(
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            recovery_binding(world, &catalog, freshness()),
            freshness(),
            next_freshness,
            checkpoint.anchor().revision(),
            checkpoint.anchor().head(),
            checkpoint.anchor().projection(),
        )
        .unwrap(),
        checkpoint.image(),
    )
    .unwrap()
    .into_engine();
    assert_eq!(
        checkpoint_recovered
            .composite_effect(parent)
            .unwrap()
            .handoff,
        SingleHopHandoffProjection::None
    );
    assert_eq!(
        checkpoint_recovered
            .component(child, TOOL_HANDOFF_COMPONENT)
            .unwrap()
            .claim_count,
        0
    );
}

#[test]
fn scoped_admission_binds_exact_operation_and_components() {
    let world = WorldId::new(9).unwrap();
    let mut engine = Engine::new(
        world,
        CatalogSet::new(&[standard_catalog()]).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let reply = coordinate(9, 21, 1);
    let dma = coordinate(9, 22, 1);
    let digest = standard_catalog().digest();
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
    let effect = EffectId::new(OperationId::new(91).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(91).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    tx(
        &mut engine,
        CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin: actor,
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
    assert_eq!(projection.operation, effect.operation());
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

#[test]
fn profile6_scoped_commit_settle_retire_release_keeps_provenance() {
    let world = WorldId::new(801).unwrap();
    let catalog = tool_dma_catalog();
    let mut engine = Engine::new(
        world,
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let mut journal = Vec::new();
    macro_rules! durable {
        ($request:expr $(,)?) => {
            engine
                .transact($request, |record| {
                    journal.extend_from_slice(record.bytes());
                    Ok::<(), ()>(())
                })
                .unwrap()
        };
    }
    let provider = coordinate(801, 802, 1);
    durable!(CommandRequest::RegisterProviderGeneration {
        coordinate: provider,
        catalog_digest: catalog.digest(),
        verifier_bindings: verifiers_for(&catalog, 0x80),
    },);
    let effect = EffectId::new(OperationId::new(8011).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(8011).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    durable!(CommandRequest::AdmitScopedCompositeEffect {
        effect,
        origin: actor,
        kind: TOOL_HANDOFF_SOURCE_COMPOSITE,
        charge_account: cser_core::ChargeAccountId::new(8011).unwrap(),
        bindings: vec![ComponentProviderBinding::new(
            TOOL_HANDOFF_SOURCE_COMPONENT,
            provider,
        )],
    },);
    durable!(CommandRequest::AddComponentClaim {
        effect,
        component: TOOL_HANDOFF_SOURCE_COMPONENT,
        actor,
        claim: ClaimId::new(8011).unwrap(),
        kind: TOOL_CLAIM_OUTCOME_SLOT,
        scope: ClaimScope::Logical,
        resource: ResourceId::new(8011).unwrap(),
        resource_generation: ResourceGeneration::new(1).unwrap(),
        units: 1,
    },);
    durable!(CommandRequest::PrepareCompositeEffect { effect, actor },);
    let commit_intent = match durable!(CommandRequest::RecordComponentCommitIntent {
        effect,
        component: TOOL_HANDOFF_SOURCE_COMPONENT,
        actor,
        operation: Digest::new([0x81; 32]),
    })
    .into_output()
    {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    let commit_verifier = ScopedEffectVerifier {
        identity: scoped_identity(&catalog, TOOL_VERIFIER, TOOL_COMMIT_RECEIPT_SCHEMA, 0x80),
    };
    let outcome = engine
        .verify_commit_outcome(&commit_intent, &commit_verifier, &())
        .unwrap();
    durable!(commit_intent.acknowledge(outcome).unwrap());

    durable!(CommandRequest::FenceProviderEffects {
        coordinate: provider,
        expected_epoch: 1,
    },);
    durable!(CommandRequest::EnterProviderSettlementOnly {
        coordinate: provider,
        expected_epoch: 2,
    },);

    let settlement = match durable!(CommandRequest::ClaimComponentSettlement {
        effect,
        component: TOOL_HANDOFF_SOURCE_COMPONENT,
        claimant: actor,
    })
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    let settlement = match durable!(
        settlement
            .record_apply_intent(Digest::new([0x82; 32]))
            .unwrap()
    )
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected apply-intent claim, got {other:?}"),
    };
    let apply_verifier = ScopedEffectVerifier {
        identity: scoped_identity(&catalog, TOOL_VERIFIER, TOOL_APPLY_RECEIPT_SCHEMA, 0x80),
    };
    let applied = engine
        .verify_apply_completion(&settlement, &apply_verifier, &())
        .unwrap();
    let settlement = match durable!(settlement.record_applied(applied).unwrap()).into_output() {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected applied claim, got {other:?}"),
    };
    let settle_verifier = ScopedEffectVerifier {
        identity: scoped_identity(
            &catalog,
            TOOL_VERIFIER,
            TOOL_SETTLEMENT_RECEIPT_SCHEMA,
            0x80,
        ),
    };
    let acknowledgement = engine
        .verify_settlement_ack(&settlement, &settle_verifier, &())
        .unwrap();
    durable!(settlement.settle(acknowledgement).unwrap());

    let evidence = engine
        .verify_component_retirement_evidence(
            effect,
            TOOL_HANDOFF_SOURCE_COMPONENT,
            ClaimId::new(8011).unwrap(),
            TOOL_EVIDENCE_OUTCOME_ACK,
            &ScopedEvidenceVerifier {
                identity: scoped_identity(&catalog, TOOL_VERIFIER, TOOL_RECEIPT_SCHEMA, 0x80),
            },
            &(),
        )
        .unwrap();
    durable!(evidence.submit());
    assert_eq!(
        engine
            .component(effect, TOOL_HANDOFF_SOURCE_COMPONENT)
            .unwrap()
            .retirement,
        cser_core::RetirementState::Retired
    );
    durable!(CommandRequest::ReleaseCompositeEffect { effect },);
    let projection = engine.composite_effect(effect).unwrap();
    assert_eq!(projection.operation, effect.operation());
    assert_eq!(
        projection.provider_bindings,
        vec![ComponentProviderBinding::new(
            TOOL_HANDOFF_SOURCE_COMPONENT,
            provider,
        )]
    );
    assert_eq!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .live_component_bindings,
        0
    );
    assert!(matches!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .state,
        ProviderEffectState::SettlementOnly { .. }
    ));
    durable!(CommandRequest::RetireProviderEffects {
        coordinate: provider,
        expected_epoch: 3,
    },);
    assert!(matches!(
        engine
            .provider_generation_projection(provider)
            .unwrap()
            .state,
        ProviderEffectState::Retired { .. }
    ));

    let next_freshness = Freshness::new(
        BootGeneration::new(2).unwrap(),
        RegistryInstance::new(1).unwrap(),
        DeviceGeneration::new(1).unwrap(),
        JournalGeneration::new(2).unwrap(),
    );
    let replayed = Engine::recover(
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            recovery_binding(world, &catalog, freshness()),
            freshness(),
            next_freshness,
            engine.revision(),
            engine.head(),
            engine.projection_digest(),
        )
        .unwrap(),
        &journal,
    )
    .unwrap()
    .into_engine();
    assert_eq!(
        replayed.composite_effect(effect).unwrap().operation,
        effect.operation()
    );
    assert_eq!(
        replayed
            .provider_generation_projection(provider)
            .unwrap()
            .live_component_bindings,
        0
    );

    let checkpoint = engine.journal_checkpoint(&journal).unwrap();
    let recovered = Engine::recover(
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        RecoveryAnchor::from_trusted_provider(
            recovery_binding(world, &catalog, freshness()),
            freshness(),
            next_freshness,
            checkpoint.anchor().revision(),
            checkpoint.anchor().head(),
            checkpoint.anchor().projection(),
        )
        .unwrap(),
        checkpoint.image(),
    )
    .unwrap()
    .into_engine();
    assert_eq!(
        recovered.composite_effect(effect).unwrap().operation,
        effect.operation()
    );
    assert_eq!(
        recovered
            .provider_generation_projection(provider)
            .unwrap()
            .live_component_bindings,
        0
    );
    assert!(matches!(
        recovered
            .provider_generation_projection(provider)
            .unwrap()
            .state,
        ProviderEffectState::Retired { .. }
    ));
}

#[test]
fn provider_rotation_rejects_active_predecessor_without_split_brain_authority() {
    let world = WorldId::new(901).unwrap();
    let catalog = tool_dma_catalog();
    let digest = catalog.digest();
    let mut engine = Engine::new(
        world,
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let predecessor = coordinate(901, 902, 1);
    let successor = coordinate(901, 902, 2);
    tx(
        &mut engine,
        CommandRequest::RegisterProviderGeneration {
            coordinate: predecessor,
            catalog_digest: digest,
            verifier_bindings: verifiers_for(&catalog, 0x90),
        },
    )
    .unwrap();
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::RegisterProviderGeneration {
                coordinate: successor,
                catalog_digest: digest,
                verifier_bindings: verifiers_for(&catalog, 0x91),
            },
        ),
        Err(CoreError::ProviderLifecycleViolation)
    );

    // A failed rotation leaves the predecessor as the sole high-water
    // authority, so an old-generation admission and commit-intent path still
    // use one coherent coordinate rather than a split-brain pair.
    let effect = EffectId::new(OperationId::new(9011).unwrap(), 1).unwrap();
    let actor = ExecutorCoordinate::new(
        ExecutorId::new(9011).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    tx(
        &mut engine,
        CommandRequest::AdmitScopedCompositeEffect {
            effect,
            origin: actor,
            kind: TOOL_HANDOFF_SOURCE_COMPOSITE,
            charge_account: cser_core::ChargeAccountId::new(9011).unwrap(),
            bindings: vec![ComponentProviderBinding::new(
                TOOL_HANDOFF_SOURCE_COMPONENT,
                predecessor,
            )],
        },
    )
    .unwrap();
    tx(
        &mut engine,
        CommandRequest::AddComponentClaim {
            effect,
            component: TOOL_HANDOFF_SOURCE_COMPONENT,
            actor,
            claim: ClaimId::new(9012).unwrap(),
            kind: TOOL_CLAIM_OUTCOME_SLOT,
            scope: ClaimScope::Logical,
            resource: ResourceId::new(9013).unwrap(),
            resource_generation: ResourceGeneration::new(1).unwrap(),
            units: 1,
        },
    )
    .unwrap();
    tx(
        &mut engine,
        CommandRequest::PrepareCompositeEffect { effect, actor },
    )
    .unwrap();
    assert!(
        tx(
            &mut engine,
            CommandRequest::RecordComponentCommitIntent {
                effect,
                component: TOOL_HANDOFF_SOURCE_COMPONENT,
                actor,
                operation: Digest::new([0x92; 32]),
            },
        )
        .is_ok()
    );
    assert!(engine.provider_generation_projection(successor).is_none());
}

#[test]
fn provider_rotation_accepts_only_effect_retired_predecessor_and_fences_old_admission() {
    let world = WorldId::new(911).unwrap();
    let catalog = tool_dma_catalog();
    let digest = catalog.digest();
    let mut engine = Engine::new(
        world,
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let predecessor = coordinate(911, 912, 1);
    let successor = coordinate(911, 912, 2);
    tx(
        &mut engine,
        CommandRequest::RegisterProviderGeneration {
            coordinate: predecessor,
            catalog_digest: digest,
            verifier_bindings: verifiers_for(&catalog, 0x93),
        },
    )
    .unwrap();
    tx(
        &mut engine,
        CommandRequest::FenceProviderEffects {
            coordinate: predecessor,
            expected_epoch: 1,
        },
    )
    .unwrap();
    tx(
        &mut engine,
        CommandRequest::EnterProviderSettlementOnly {
            coordinate: predecessor,
            expected_epoch: 2,
        },
    )
    .unwrap();
    tx(
        &mut engine,
        CommandRequest::RetireProviderEffects {
            coordinate: predecessor,
            expected_epoch: 3,
        },
    )
    .unwrap();
    tx(
        &mut engine,
        CommandRequest::RegisterProviderGeneration {
            coordinate: successor,
            catalog_digest: digest,
            verifier_bindings: verifiers_for(&catalog, 0x94),
        },
    )
    .unwrap();

    let actor = ExecutorCoordinate::new(
        ExecutorId::new(9111).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    let old_effect = EffectId::new(OperationId::new(9111).unwrap(), 1).unwrap();
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::AdmitScopedCompositeEffect {
                effect: old_effect,
                origin: actor,
                kind: TOOL_HANDOFF_SOURCE_COMPOSITE,
                charge_account: cser_core::ChargeAccountId::new(9111).unwrap(),
                bindings: vec![ComponentProviderBinding::new(
                    TOOL_HANDOFF_SOURCE_COMPONENT,
                    predecessor,
                )],
            },
        ),
        Err(CoreError::ProviderLifecycleViolation)
    );
    let current_effect = EffectId::new(OperationId::new(9112).unwrap(), 1).unwrap();
    tx(
        &mut engine,
        CommandRequest::AdmitScopedCompositeEffect {
            effect: current_effect,
            origin: actor,
            kind: TOOL_HANDOFF_SOURCE_COMPOSITE,
            charge_account: cser_core::ChargeAccountId::new(9112).unwrap(),
            bindings: vec![ComponentProviderBinding::new(
                TOOL_HANDOFF_SOURCE_COMPONENT,
                successor,
            )],
        },
    )
    .unwrap();
    assert!(matches!(
        engine
            .provider_generation_projection(predecessor)
            .unwrap()
            .state,
        ProviderEffectState::Retired { .. }
    ));
    assert!(matches!(
        engine
            .provider_generation_projection(successor)
            .unwrap()
            .state,
        ProviderEffectState::Active
    ));
}

#[test]
fn settlement_only_predecessor_with_indeterminate_effect_does_not_block_successor() {
    let world = WorldId::new(921).unwrap();
    let catalog = tool_dma_catalog();
    let digest = catalog.digest();
    let mut engine = Engine::new(
        world,
        CatalogSet::new(std::slice::from_ref(&catalog)).unwrap(),
        CoreLimits::bounded_default(),
        freshness(),
    );
    let mut journal = Vec::new();
    macro_rules! durable {
        ($request:expr $(,)?) => {
            engine
                .transact($request, |record| {
                    journal.extend_from_slice(record.bytes());
                    Ok::<(), ()>(())
                })
                .unwrap()
        };
    }

    let predecessor = coordinate(921, 922, 1);
    let successor = coordinate(921, 922, 2);
    durable!(CommandRequest::RegisterProviderGeneration {
        coordinate: predecessor,
        catalog_digest: digest,
        verifier_bindings: verifiers_for(&catalog, 0x95),
    });

    let old_effect = EffectId::new(OperationId::new(9211).unwrap(), 1).unwrap();
    let old_actor = ExecutorCoordinate::new(
        ExecutorId::new(9211).unwrap(),
        ExecutorGeneration::new(1).unwrap(),
    );
    durable!(CommandRequest::AdmitScopedCompositeEffect {
        effect: old_effect,
        origin: old_actor,
        kind: TOOL_HANDOFF_SOURCE_COMPOSITE,
        charge_account: cser_core::ChargeAccountId::new(9211).unwrap(),
        bindings: vec![ComponentProviderBinding::new(
            TOOL_HANDOFF_SOURCE_COMPONENT,
            predecessor,
        )],
    });
    durable!(CommandRequest::AddComponentClaim {
        effect: old_effect,
        component: TOOL_HANDOFF_SOURCE_COMPONENT,
        actor: old_actor,
        claim: ClaimId::new(9211).unwrap(),
        kind: TOOL_CLAIM_OUTCOME_SLOT,
        scope: ClaimScope::Logical,
        resource: ResourceId::new(9211).unwrap(),
        resource_generation: ResourceGeneration::new(1).unwrap(),
        units: 1,
    });
    durable!(CommandRequest::PrepareCompositeEffect {
        effect: old_effect,
        actor: old_actor,
    });
    let commit_intent = match durable!(CommandRequest::RecordComponentCommitIntent {
        effect: old_effect,
        component: TOOL_HANDOFF_SOURCE_COMPONENT,
        actor: old_actor,
        operation: Digest::new([0x96; 32]),
    })
    .into_output()
    {
        TransitionOutput::CommitIntent(intent) => intent,
        other => panic!("expected commit intent, got {other:?}"),
    };
    let outcome = engine
        .verify_commit_outcome(
            &commit_intent,
            &ScopedEffectVerifier {
                identity: scoped_identity(
                    &catalog,
                    TOOL_VERIFIER,
                    TOOL_COMMIT_RECEIPT_SCHEMA,
                    0x95,
                ),
            },
            &(),
        )
        .unwrap();
    durable!(commit_intent.acknowledge(outcome).unwrap());
    durable!(CommandRequest::FenceProviderEffects {
        coordinate: predecessor,
        expected_epoch: 1,
    });
    durable!(CommandRequest::EnterProviderSettlementOnly {
        coordinate: predecessor,
        expected_epoch: 2,
    });

    let settlement = match durable!(CommandRequest::ClaimComponentSettlement {
        effect: old_effect,
        component: TOOL_HANDOFF_SOURCE_COMPONENT,
        claimant: old_actor,
    })
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected settlement claim, got {other:?}"),
    };
    durable!(settlement.mark_indeterminate(Digest::new([0x97; 32])));

    // The unresolved predecessor remains the exact owner of its old effect,
    // while the successor becomes the only generation allowed to admit work.
    durable!(CommandRequest::RegisterProviderGeneration {
        coordinate: successor,
        catalog_digest: digest,
        verifier_bindings: verifiers_for(&catalog, 0x98),
    });
    let _old_reconciliation = match durable!(CommandRequest::ClaimComponentSettlement {
        effect: old_effect,
        component: TOOL_HANDOFF_SOURCE_COMPONENT,
        claimant: old_actor,
    })
    .into_output()
    {
        TransitionOutput::SettlementClaim(claim) => claim,
        other => panic!("expected old-generation reconciliation claim, got {other:?}"),
    };
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::RetireProviderEffects {
                coordinate: predecessor,
                expected_epoch: 3,
            },
        ),
        Err(CoreError::ProviderEffectsLive)
    );
    assert_eq!(
        tx(
            &mut engine,
            CommandRequest::AdmitScopedCompositeEffect {
                effect: EffectId::new(OperationId::new(9212).unwrap(), 1).unwrap(),
                origin: old_actor,
                kind: TOOL_HANDOFF_SOURCE_COMPOSITE,
                charge_account: cser_core::ChargeAccountId::new(9212).unwrap(),
                bindings: vec![ComponentProviderBinding::new(
                    TOOL_HANDOFF_SOURCE_COMPONENT,
                    predecessor,
                )],
            },
        ),
        Err(CoreError::ProviderLifecycleViolation)
    );
    let new_effect = EffectId::new(OperationId::new(9213).unwrap(), 1).unwrap();
    durable!(CommandRequest::AdmitScopedCompositeEffect {
        effect: new_effect,
        origin: old_actor,
        kind: TOOL_HANDOFF_SOURCE_COMPOSITE,
        charge_account: cser_core::ChargeAccountId::new(9213).unwrap(),
        bindings: vec![ComponentProviderBinding::new(
            TOOL_HANDOFF_SOURCE_COMPONENT,
            successor,
        )],
    });
    let old_obligations = engine.provider_obligations(predecessor);
    assert_eq!(old_obligations.len(), 1);
    assert_eq!(old_obligations[0].effect, old_effect);
    assert_eq!(old_obligations[0].provider, predecessor);
    assert_eq!(
        old_obligations[0].outcome,
        cser_core::OutcomeState::Indeterminate(Digest::new([0x97; 32]))
    );
    assert_eq!(engine.provider_obligations(successor)[0].effect, new_effect);

    let next_freshness = Freshness::new(
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
            next_freshness,
            engine.revision(),
            engine.head(),
            engine.projection_digest(),
        )
        .unwrap(),
        &journal,
    )
    .unwrap()
    .into_engine();
    assert!(matches!(
        recovered
            .provider_generation_projection(predecessor)
            .unwrap()
            .state,
        ProviderEffectState::SettlementOnly { epoch: 3 }
    ));
    assert_eq!(
        recovered
            .provider_generation_projection(successor)
            .unwrap()
            .state,
        ProviderEffectState::Active
    );
    assert_eq!(
        recovered.provider_obligations(predecessor)[0].effect,
        old_effect
    );
    assert_eq!(
        recovered.provider_obligations(successor)[0].effect,
        new_effect
    );
}
