// SPDX-License-Identifier: MPL-2.0

//! Development-only negative durability probe for the focused reply profile.

use alloc::vec;
use core::convert::Infallible;

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration,
    ChargeAccountId, CommandRequest, ComponentProviderBinding, CoreLimits, Digest, EffectId,
    Freshness, JournalGeneration, JournalRecord, OperationId, PrincipalId, PrincipalIncarnation,
    ProviderCoordinate, ProviderGeneration, ProviderId, RegistryInstance, RootId,
    TransitionDurability, TxError, VerifierBinding, VerifierGeneration, WorldId, standard_catalog,
};
use ostd::prelude::println;

use super::OstdCserRuntime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnavailableJournalError {
    NoDurableProvider,
}

struct UnavailableJournal;

impl TransitionDurability for UnavailableJournal {
    type Error = UnavailableJournalError;

    fn persist_transition(
        &mut self,
        record: &JournalRecord,
        resulting_freshness: Freshness,
        _resulting_projection: Digest,
    ) -> Result<(), Self::Error> {
        assert!(!record.bytes().is_empty());
        assert_ne!(resulting_freshness.boot().get(), 0);
        Err(UnavailableJournalError::NoDurableProvider)
    }
}

/// Requires a failed durable transition to latch recovery-required without
/// publishing the candidate estate.
pub(super) fn run_boot_probe() {
    let world = WorldId::new(1).expect("spike world is non-zero");
    let root = RootId::new(1).expect("spike root is non-zero");
    let principal = PrincipalId::new(1).expect("spike principal is non-zero");
    let origin = PrincipalIncarnation::new(principal, 1).expect("spike incarnation is non-zero");
    let freshness = Freshness::new(
        BootGeneration::new(1).expect("spike boot is non-zero"),
        RegistryInstance::new(1).expect("spike registry instance is non-zero"),
        1,
        cser_core::DeviceGeneration::new(1).expect("spike device generation is non-zero"),
        JournalGeneration::new(1).expect("spike journal is non-zero"),
    )
    .expect("spike freshness is complete");
    let catalog = standard_catalog();
    let provider = ProviderCoordinate::new(
        world,
        ProviderId::new(1).expect("spike provider is non-zero"),
        ProviderGeneration::new(1).expect("spike provider generation is non-zero"),
    );
    let verifier_generation =
        VerifierGeneration::new(1).expect("spike verifier generation is non-zero");
    let verifier_bindings = catalog
        .verifier_class_bindings()
        .into_iter()
        .enumerate()
        .map(|(index, class)| {
            VerifierBinding::new(
                class.verifier(),
                verifier_generation,
                class.receipt_schema(),
                Digest::new([0x40u8.wrapping_add(index as u8); 32]),
            )
            .expect("spike verifier binding is valid")
        })
        .collect();
    let mut engine = cser_core::Engine::new(
        world,
        catalog.clone(),
        CoreLimits::bounded_default(),
        freshness,
    );
    engine
        .transact(
            CommandRequest::RegisterProviderGeneration {
                coordinate: provider,
                catalog_digest: catalog.digest(),
                verifier_bindings,
            },
            |_| Ok::<(), Infallible>(()),
        )
        .expect("spike provider setup is valid");
    let base_revision = engine.revision();
    let runtime = OstdCserRuntime::from_engine(engine, UnavailableJournal);
    let effect = EffectId::new(root, 1).expect("spike effect is non-zero");
    let command = CommandRequest::AdmitScopedCompositeEffect {
        effect,
        operation: OperationId::new(1).expect("spike operation is non-zero"),
        origin,
        binding_generation: 1,
        kind: AGENT_OPERATION_COMPOSITE,
        charge_account: ChargeAccountId::new(1).expect("spike account is non-zero"),
        bindings: vec![
            ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, provider),
            ComponentProviderBinding::new(AGENT_COMPONENT_DMA, provider),
        ],
    };

    assert!(matches!(
        runtime.transact(command),
        Err(TxError::Persist(UnavailableJournalError::NoDurableProvider))
    ));
    let (revision, estate_absent, recovery_required) = runtime.observe(|engine| {
        (
            engine.revision(),
            engine.composite_effect(effect).is_none(),
            engine.pressure().persistence_recovery_required,
        )
    });
    assert_eq!(revision, base_revision);
    assert!(estate_absent);
    assert!(recovery_required);
    println!(
        "CSER_CORE_RUNTIME_SPIKE PASS writer=portable_core legacy_runtime=false \
         live_ingress=false durable_provider=unavailable fail_closed=true"
    );
}
