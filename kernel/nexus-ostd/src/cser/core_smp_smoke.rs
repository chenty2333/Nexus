// SPDX-License-Identifier: MPL-2.0

//! A narrow real-SMP execution witness.
//!
//! CPU1 receives one asynchronous IPI and records only its CPU number.  The
//! CSER transition stays on the BSP and is deliberately a fail-closed durable
//! write probe: interrupt context never takes the runtime mutex or runs a
//! sleepable transaction.

use core::sync::atomic::{AtomicUsize, Ordering};

use cser_core::{
    AGENT_OPERATION_COMPOSITE, BootGeneration, ChargeAccountId, CommandRequest, CoreLimits,
    EffectId, Freshness, JournalGeneration, JournalRecord, PrincipalId, PrincipalIncarnation,
    RegistryInstance, RootId, TransitionDurability, TxError, standard_catalog,
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
    let runtime = OstdCserRuntime::from_engine(
        cser_core::Engine::new(standard_catalog(), CoreLimits::bounded_default(), freshness),
        UnavailableJournal,
    );
    let effect = EffectId::new(root, 1).expect("smoke effect is non-zero");
    runtime.set_serialization_timing(true);
    assert!(matches!(
        runtime.transact(CommandRequest::CreateCompositeEffect {
            effect,
            origin,
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: ChargeAccountId::new(1).expect("smoke account is non-zero"),
        }),
        Err(TxError::Persist(UnavailableJournalError::NoDurableProvider))
    ));
    runtime.observe(|engine| {
        assert_eq!(engine.revision(), 0);
        assert!(engine.composite_effect(effect).is_none());
        assert!(engine.pressure().persistence_recovery_required);
    });
    let metrics = runtime.serialization_metrics();
    assert_eq!(metrics.transactions, 1);
    runtime.set_serialization_timing(false);
    metrics
}
