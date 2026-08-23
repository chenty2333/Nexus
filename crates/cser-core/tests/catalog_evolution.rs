#[allow(dead_code)]
mod support;

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE,
    CatalogEvolutionDurability, CatalogSet, CheckpointAnchor, CommandRequest as Command,
    ComponentProviderBinding, CoreError, Engine, PreparedCheckpoint, ProviderCoordinate,
    ProviderGeneration, ProviderId, TransitionEvent, TxError, VerifierClassBinding, WorldId,
    standard_catalog, tool_dma_catalog,
};
use support::{
    EFFECT_COMPONENT, Harness, admit_command, charge, effect, executor, freshness, recovery_anchor,
    test_world, verifier_binding,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistenceFailure {
    Stage,
    Anchor,
}

#[derive(Default)]
struct MemoryCheckpoint {
    image: Vec<u8>,
    fail_stage: bool,
    fail_anchor: bool,
    stage_calls: usize,
    anchor_calls: usize,
}

impl CatalogEvolutionDurability for MemoryCheckpoint {
    type Error = PersistenceFailure;

    fn persist_catalog_evolution(
        &mut self,
        prepared: &PreparedCheckpoint,
    ) -> Result<(), Self::Error> {
        self.stage_calls += 1;
        if self.fail_stage {
            return Err(PersistenceFailure::Stage);
        }
        self.image.clear();
        prepared
            .plan()
            .write_to(&mut self.image)
            .expect("Vec checkpoint sink is infallible");
        Ok(())
    }

    fn anchor_catalog_evolution(&mut self, _anchor: CheckpointAnchor) -> Result<(), Self::Error> {
        self.anchor_calls += 1;
        if self.fail_anchor {
            return Err(PersistenceFailure::Anchor);
        }
        Ok(())
    }
}

fn provider_with_catalog(
    provider_id: u64,
    catalog: &cser_core::DomainCatalog,
) -> (ProviderCoordinate, Command) {
    let coordinate = ProviderCoordinate::new(
        test_world(),
        ProviderId::new(provider_id).unwrap(),
        ProviderGeneration::new(1).unwrap(),
    );
    let command = Command::RegisterProviderGeneration {
        coordinate,
        catalog_digest: catalog.digest(),
        verifier_bindings: catalog
            .verifier_class_bindings()
            .into_iter()
            .map(|class: VerifierClassBinding| {
                verifier_binding(class.verifier(), class.receipt_schema())
            })
            .collect(),
    };
    (coordinate, command)
}

#[test]
fn append_only_checkpoint_rebind_preserves_old_effect_and_recovers_new_admission() {
    let historical = tool_dma_catalog();
    let current = standard_catalog();
    let old_effect = effect(0xca71, 1);
    let mut harness = Harness::new();
    harness.tx(admit_command(old_effect, 0xca71)).unwrap();

    let evolved = CatalogSet::new(&[historical.clone(), current.clone()]).unwrap();
    let mut persistence = MemoryCheckpoint::default();
    let receipt = harness
        .engine
        .evolve_catalog_set_streaming(evolved.clone(), &mut persistence)
        .unwrap();
    assert_eq!(receipt.event(), TransitionEvent::RecoveryCheckpointed);
    assert_eq!(harness.engine.catalog_set_digest(), evolved.digest());
    assert_eq!(persistence.stage_calls, 1);
    assert_eq!(persistence.anchor_calls, 1);

    // The streaming checkpoint replaced the old prefix. New ordinary records
    // extend that exact image under the evolved recovery binding.
    harness.journal = persistence.image;
    let (new_provider, register) = provider_with_catalog(2, &current);
    harness.tx(register).unwrap();
    let new_effect = effect(0xca72, 1);
    harness
        .tx(Command::AdmitScopedCompositeEffect {
            effect: new_effect,
            origin: executor(0xca72, 1),
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: charge(0xca72),
            bindings: vec![
                ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, new_provider),
                ComponentProviderBinding::new(AGENT_COMPONENT_DMA, new_provider),
            ],
        })
        .unwrap();

    assert_eq!(
        harness
            .engine
            .composite_effect(old_effect)
            .unwrap()
            .catalog_digest,
        historical.digest()
    );
    assert_eq!(
        harness
            .engine
            .composite_effect(new_effect)
            .unwrap()
            .catalog_digest,
        current.digest()
    );

    let revision = harness.engine.revision();
    let head = harness.engine.head();
    let projection = harness.engine.projection_digest();
    let recovered = Engine::recover(
        evolved,
        cser_core::CoreLimits::bounded_default(),
        recovery_anchor(
            harness.engine.catalog_set_digest(),
            freshness(1, 1, 1, 1),
            freshness(2, 1, 1, 2),
            revision,
            head,
            projection,
        ),
        &harness.journal,
    )
    .unwrap()
    .into_engine();
    assert_eq!(
        recovered
            .composite_effect(old_effect)
            .unwrap()
            .catalog_digest,
        historical.digest()
    );
    assert_eq!(
        recovered
            .composite_effect(new_effect)
            .unwrap()
            .catalog_digest,
        current.digest()
    );
    assert_eq!(
        recovered
            .component(old_effect, EFFECT_COMPONENT)
            .unwrap()
            .effect,
        old_effect
    );
    assert_eq!(
        recovered.catalog_set_digest(),
        recovered.catalog_set().digest()
    );
}

#[test]
fn removal_replacement_and_failed_durability_never_publish_catalog_availability() {
    let historical = tool_dma_catalog();
    let current = standard_catalog();
    let original = CatalogSet::new(core::slice::from_ref(&historical)).unwrap();
    let replacement = CatalogSet::new(core::slice::from_ref(&current)).unwrap();
    let evolved = CatalogSet::new(&[historical, current]).unwrap();

    let mut harness = Harness::new();
    let original_revision = harness.engine.revision();
    let original_head = harness.engine.head();
    let original_projection = harness.engine.projection_digest();
    let mut untouched = MemoryCheckpoint::default();
    assert!(matches!(
        harness
            .engine
            .evolve_catalog_set_streaming(replacement, &mut untouched),
        Err(TxError::Core(CoreError::SchemaMismatch))
    ));
    assert_eq!(untouched.stage_calls, 0);
    assert_eq!(untouched.anchor_calls, 0);
    assert_eq!(harness.engine.catalog_set_digest(), original.digest());
    assert_eq!(harness.engine.revision(), original_revision);
    assert_eq!(harness.engine.head(), original_head);
    assert_eq!(harness.engine.projection_digest(), original_projection);

    let mut stage_failure = MemoryCheckpoint {
        fail_stage: true,
        ..MemoryCheckpoint::default()
    };
    assert!(matches!(
        harness
            .engine
            .evolve_catalog_set_streaming(evolved, &mut stage_failure),
        Err(TxError::Persist(PersistenceFailure::Stage))
    ));
    assert_eq!(stage_failure.stage_calls, 1);
    assert_eq!(stage_failure.anchor_calls, 0);
    assert_eq!(harness.engine.catalog_set_digest(), original.digest());
    assert_eq!(harness.engine.revision(), original_revision);
    assert_eq!(harness.engine.head(), original_head);
    assert_eq!(harness.engine.projection_digest(), original_projection);
}

#[test]
fn anchor_failure_keeps_the_old_catalog_generation_published() {
    let historical = tool_dma_catalog();
    let evolved = CatalogSet::new(&[historical.clone(), standard_catalog()]).unwrap();
    let original = CatalogSet::new(core::slice::from_ref(&historical)).unwrap();
    let mut harness = Harness::new();
    let revision = harness.engine.revision();
    let head = harness.engine.head();
    let projection = harness.engine.projection_digest();
    let mut persistence = MemoryCheckpoint {
        fail_anchor: true,
        ..MemoryCheckpoint::default()
    };

    assert!(matches!(
        harness
            .engine
            .evolve_catalog_set_streaming(evolved, &mut persistence),
        Err(TxError::Persist(PersistenceFailure::Anchor))
    ));
    assert_eq!(persistence.stage_calls, 1);
    assert_eq!(persistence.anchor_calls, 1);
    assert_eq!(harness.engine.catalog_set_digest(), original.digest());
    assert_eq!(harness.engine.revision(), revision);
    assert_eq!(harness.engine.head(), head);
    assert_eq!(harness.engine.projection_digest(), projection);
}

#[test]
fn recovery_rejects_the_old_or_unrelated_catalog_set_after_rebind() {
    let historical = tool_dma_catalog();
    let current = standard_catalog();
    let evolved = CatalogSet::new(&[historical.clone(), current.clone()]).unwrap();
    let mut harness = Harness::new();
    let mut persistence = MemoryCheckpoint::default();
    harness
        .engine
        .evolve_catalog_set_streaming(evolved.clone(), &mut persistence)
        .unwrap();
    let revision = harness.engine.revision();
    let head = harness.engine.head();
    let projection = harness.engine.projection_digest();

    for wrong in [
        CatalogSet::new(core::slice::from_ref(&historical)).unwrap(),
        CatalogSet::new(core::slice::from_ref(&current)).unwrap(),
    ] {
        let result = Engine::recover(
            wrong,
            cser_core::CoreLimits::bounded_default(),
            recovery_anchor(
                evolved.digest(),
                freshness(1, 1, 1, 1),
                freshness(2, 1, 1, 2),
                revision,
                head,
                projection,
            ),
            &persistence.image,
        );
        assert!(matches!(result, Err(CoreError::SchemaMismatch)));
    }
}

#[test]
fn provider_coordinates_remain_world_scoped_after_evolution() {
    let world = WorldId::new(test_world().get() + 1).unwrap();
    let catalog = standard_catalog();
    let set = CatalogSet::new(&[tool_dma_catalog(), catalog.clone()]).unwrap();
    let mut harness = Harness::new();
    let mut persistence = MemoryCheckpoint::default();
    harness
        .engine
        .evolve_catalog_set_streaming(set, &mut persistence)
        .unwrap();
    let coordinate = ProviderCoordinate::new(
        world,
        ProviderId::new(2).unwrap(),
        ProviderGeneration::new(1).unwrap(),
    );
    let result = harness.tx(Command::RegisterProviderGeneration {
        coordinate,
        catalog_digest: catalog.digest(),
        verifier_bindings: catalog
            .verifier_class_bindings()
            .into_iter()
            .map(|class| verifier_binding(class.verifier(), class.receipt_schema()))
            .collect(),
    });
    assert_eq!(result, Err(CoreError::WorldMismatch));
}
