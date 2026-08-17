// SPDX-License-Identifier: MPL-2.0

//! A narrow real-SMP execution witness.
//!
//! CPU1 receives one asynchronous IPI and records only its CPU number.  The
//! CSER transition stays on the BSP and is deliberately a fail-closed durable
//! write probe: interrupt context never takes the runtime mutex or runs a
//! sleepable transaction.

use alloc::vec;
use core::convert::Infallible;
use core::sync::atomic::{AtomicUsize, Ordering};

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration,
    ChargeAccountId, CommandRequest, ComponentProviderBinding, CoreLimits, Digest, EffectId,
    Freshness, JournalGeneration, JournalRecord, OperationId, PrincipalId, PrincipalIncarnation,
    ProviderCoordinate, ProviderGeneration, ProviderId, RegistryInstance, RootId,
    TransitionDurability, TxError, VerifierBinding, VerifierGeneration, WorldId, standard_catalog,
};
use ostd::{
    cpu::{CpuId, CpuSet, num_cpus},
    power::{ExitCode, poweroff},
    prelude::println,
    smp,
};

use super::core_runtime::OstdCserRuntime;

const CPU_NOT_RECORDED: usize = usize::MAX;
const IPI_WAIT_YIELDS: usize = 10_000;

static IPI_CPU: AtomicUsize = AtomicUsize::new(CPU_NOT_RECORDED);

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

/// Runs in IPI context with local IRQs disabled. Keep this nonblocking: no
/// allocation, locks, transaction, output, or scheduler operation is allowed.
fn record_cpu1_ipi() {
    let current = CpuId::current_racy();
    let observed = if current == CpuId::bsp() {
        0
    } else if current == CpuId::new(1) {
        1
    } else {
        num_cpus()
    };
    IPI_CPU.store(observed, Ordering::Release);
}

pub(crate) fn launch() -> ! {
    assert_eq!(num_cpus(), 2, "cser SMP smoke requires exactly two CPUs");
    assert_eq!(
        CpuId::current_racy(),
        CpuId::bsp(),
        "SMP smoke must start on BSP"
    );

    IPI_CPU.store(CPU_NOT_RECORDED, Ordering::Release);
    smp::inter_processor_call(&CpuSet::from(CpuId::new(1)), record_cpu1_ipi);
    for _ in 0..IPI_WAIT_YIELDS {
        if IPI_CPU.load(Ordering::Acquire) != CPU_NOT_RECORDED {
            break;
        }
        core::hint::spin_loop();
    }
    assert_eq!(
        IPI_CPU.load(Ordering::Acquire),
        1,
        "CPU1 IPI did not complete"
    );

    assert_eq!(
        CpuId::current_racy(),
        CpuId::bsp(),
        "CSER transaction must remain on BSP"
    );
    let metrics = run_bsp_fail_closed_persistence_smoke();
    println!(
        "CSER_SMP_IPI PASS cpus=2 cpu1=1 callback=atomic-only wait=yields-bounded \
         scheduler=bsp-only cross_cpu_transactions=false persistence=fail-closed \
         transactions={} lock_wait_cycles={} lock_hold_cycles={} tcg=multi",
        metrics.transactions, metrics.lock_wait_cycles, metrics.lock_hold_cycles,
    );
    poweroff(ExitCode::Success);
}

fn run_bsp_fail_closed_persistence_smoke() -> super::core_runtime::RuntimeSerializationMetrics {
    let world = WorldId::new(1).expect("smoke world is non-zero");
    let root = RootId::new(1).expect("smoke root is non-zero");
    let principal = PrincipalId::new(1).expect("smoke principal is non-zero");
    let origin = PrincipalIncarnation::new(principal, 1).expect("smoke incarnation is non-zero");
    let freshness = Freshness::new(
        BootGeneration::new(1).expect("smoke boot is non-zero"),
        RegistryInstance::new(1).expect("smoke registry instance is non-zero"),
        1,
        cser_core::DeviceGeneration::new(1).expect("smoke device generation is non-zero"),
        JournalGeneration::new(1).expect("smoke journal is non-zero"),
    )
    .expect("smoke freshness is complete");
    let catalog = standard_catalog();
    let provider = ProviderCoordinate::new(
        world,
        ProviderId::new(1).expect("smoke provider is non-zero"),
        ProviderGeneration::new(1).expect("smoke provider generation is non-zero"),
    );
    let verifier_generation =
        VerifierGeneration::new(1).expect("smoke verifier generation is non-zero");
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
            .expect("smoke verifier binding is valid")
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
        .expect("smoke provider setup is valid");
    let base_revision = engine.revision();
    let runtime = OstdCserRuntime::from_engine(engine, UnavailableJournal);
    let effect = EffectId::new(root, 1).expect("smoke effect is non-zero");
    runtime.set_serialization_timing(true);
    assert!(matches!(
        runtime.transact(CommandRequest::AdmitScopedCompositeEffect {
            effect,
            operation: OperationId::new(1).expect("smoke operation is non-zero"),
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: ChargeAccountId::new(1).expect("smoke account is non-zero"),
            bindings: vec![
                ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, provider),
                ComponentProviderBinding::new(AGENT_COMPONENT_DMA, provider),
            ],
        }),
        Err(TxError::Persist(UnavailableJournalError::NoDurableProvider))
    ));
    runtime.observe(|engine| {
        assert_eq!(engine.revision(), base_revision);
        assert!(engine.composite_effect(effect).is_none());
        assert!(engine.pressure().persistence_recovery_required);
    });
    let metrics = runtime.serialization_metrics();
    assert_eq!(metrics.transactions, 1);
    runtime.set_serialization_timing(false);
    metrics
}
