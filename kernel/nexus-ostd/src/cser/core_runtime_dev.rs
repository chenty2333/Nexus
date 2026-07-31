// SPDX-License-Identifier: MPL-2.0

//! Development-only negative durability probe for the focused reply profile.

use cser_core::{
    AGENT_OPERATION_COMPOSITE, BootGeneration, ChargeAccountId, CommandRequest, CoreLimits,
    EffectId, Freshness, JournalGeneration, JournalRecord, PrincipalId, PrincipalIncarnation,
    RegistryInstance, RootId, TransitionDurability, TxError, standard_catalog,
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
    ) -> Result<(), Self::Error> {
        assert!(!record.bytes().is_empty());
        assert_ne!(resulting_freshness.boot().get(), 0);
        Err(UnavailableJournalError::NoDurableProvider)
    }
}

/// Requires a failed durable transition to latch recovery-required without
/// publishing the candidate estate.
pub(super) fn run_boot_probe() {
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
    let engine =
        cser_core::Engine::new(standard_catalog(), CoreLimits::bounded_default(), freshness);
    let runtime = OstdCserRuntime::from_engine(engine, UnavailableJournal);
    let effect = EffectId::new(root, 1).expect("spike effect is non-zero");
    let command = CommandRequest::CreateCompositeEffect {
        effect,
        origin,
        binding_generation: 1,
        kind: AGENT_OPERATION_COMPOSITE,
        charge_account: ChargeAccountId::new(1).expect("spike account is non-zero"),
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
    assert_eq!(revision, 0);
    assert!(estate_absent);
    assert!(recovery_required);
    println!(
        "CSER_CORE_RUNTIME_SPIKE PASS writer=portable_core legacy_runtime=false \
         live_ingress=false durable_provider=unavailable fail_closed=true"
    );
}
