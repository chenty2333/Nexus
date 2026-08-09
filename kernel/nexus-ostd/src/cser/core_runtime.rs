// SPDX-License-Identifier: MPL-2.0

//! Production OSTD ownership boundary for the portable CSER core.
//!
//! This module owns no global instance. The production bootstrap constructs one
//! recovered owner and shares it with every ingress adapter that may mutate the
//! engine.
//!
//! Transactions hold an OSTD sleepable [`Mutex`] across the journal append and
//! durability barrier required by [`Engine::transact_durable`].  Consequently callers
//! must enter through a manager/task context which may block.  IRQ handlers,
//! atomic callbacks, and code already holding a spin lock may only enqueue work
//! for that owner; they must never call [`OstdCserRuntime::transact`] directly.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use cser_core::{
    Command, CoreError, CoreLimits, Digest, DomainCatalog, Engine, JournalRepair, RecoveryAnchor,
    TransitionDurability, TransitionReceipt, TxError,
};
use ostd::{prelude::*, sync::Mutex};

/// Exact replay boundary returned before a recovered runtime becomes eligible
/// for later publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OstdRecoveryBoundary {
    acknowledged_revision: u64,
    acknowledged_head: Digest,
    journal_repair: Option<JournalRepair>,
}

impl OstdRecoveryBoundary {
    /// Returns the last replayed journal revision.
    pub(crate) const fn acknowledged_revision(self) -> u64 {
        self.acknowledged_revision
    }

    /// Returns the exact replayed journal head.
    pub(crate) const fn acknowledged_head(self) -> Digest {
        self.acknowledged_head
    }

    /// Returns the first incomplete-tail byte, if recovery found one.
    ///
    /// The core keeps such an engine recovery-blocked until storage repairs the
    /// tail and recovery is run again.
    pub(crate) const fn torn_tail(self) -> Option<usize> {
        match self.journal_repair {
            Some(JournalRepair::TornTail { offset }) => Some(offset),
            Some(JournalRepair::UnanchoredSuffix { .. }) | None => None,
        }
    }

    /// Returns the exact suffix repair required before activation.
    pub(crate) const fn journal_repair(self) -> Option<JournalRepair> {
        self.journal_repair
    }
}

#[derive(Debug)]
struct RuntimeState<P> {
    engine: Engine,
    persistence: P,
}

/// Snapshot of optional timing taken around the runtime's writer mutex.
///
/// The cycle fields are intentionally an aggregate rather than a latency
/// promise: sampling is off by default, and a TSC sample is useful for the
/// single-CPU QEMU measurement profile, not as a portable wall-clock.  A
/// concurrent caller may update the counters while this snapshot is read.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RuntimeSerializationMetrics {
    /// Number of durable transitions sampled while timing was enabled.
    pub(crate) transactions: u64,
    /// Sum of cycles spent waiting to acquire the authoritative writer lock.
    pub(crate) lock_wait_cycles: u64,
    /// Largest single sampled writer-lock wait.
    pub(crate) max_lock_wait_cycles: u64,
    /// Sum of cycles spent holding the writer lock, including durability I/O.
    pub(crate) lock_hold_cycles: u64,
    /// Largest single sampled writer-lock hold.
    pub(crate) max_lock_hold_cycles: u64,
}

/// Default-off measurement state that is deliberately outside the durable
/// transition state.  It cannot affect a journal record, anchor, or recovery
/// decision.
#[derive(Debug)]
struct RuntimeSerializationTelemetry {
    enabled: AtomicBool,
    transactions: AtomicU64,
    lock_wait_cycles: AtomicU64,
    max_lock_wait_cycles: AtomicU64,
    lock_hold_cycles: AtomicU64,
    max_lock_hold_cycles: AtomicU64,
}

impl RuntimeSerializationTelemetry {
    const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            transactions: AtomicU64::new(0),
            lock_wait_cycles: AtomicU64::new(0),
            max_lock_wait_cycles: AtomicU64::new(0),
            lock_hold_cycles: AtomicU64::new(0),
            max_lock_hold_cycles: AtomicU64::new(0),
        }
    }

    fn set_enabled(&self, enabled: bool) {
        self.transactions.store(0, Ordering::Relaxed);
        self.lock_wait_cycles.store(0, Ordering::Relaxed);
        self.max_lock_wait_cycles.store(0, Ordering::Relaxed);
        self.lock_hold_cycles.store(0, Ordering::Relaxed);
        self.max_lock_hold_cycles.store(0, Ordering::Relaxed);
        self.enabled.store(enabled, Ordering::Release);
    }

    fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    fn record(&self, lock_wait_cycles: u64, lock_hold_cycles: u64) {
        saturating_atomic_add(&self.transactions, 1);
        saturating_atomic_add(&self.lock_wait_cycles, lock_wait_cycles);
        self.max_lock_wait_cycles
            .fetch_max(lock_wait_cycles, Ordering::Relaxed);
        saturating_atomic_add(&self.lock_hold_cycles, lock_hold_cycles);
        self.max_lock_hold_cycles
            .fetch_max(lock_hold_cycles, Ordering::Relaxed);
    }

    fn snapshot(&self) -> RuntimeSerializationMetrics {
        RuntimeSerializationMetrics {
            transactions: self.transactions.load(Ordering::Relaxed),
            lock_wait_cycles: self.lock_wait_cycles.load(Ordering::Relaxed),
            max_lock_wait_cycles: self.max_lock_wait_cycles.load(Ordering::Relaxed),
            lock_hold_cycles: self.lock_hold_cycles.load(Ordering::Relaxed),
            max_lock_hold_cycles: self.max_lock_hold_cycles.load(Ordering::Relaxed),
        }
    }
}

fn saturating_atomic_add(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(amount))
    });
}

#[inline]
fn timing_cycles() -> u64 {
    // The production and QEMU profiles are x86_64.  Keep non-x86 builds
    // compilable; their default-off telemetry still records transaction counts
    // but deliberately reports no fabricated timing.
    #[cfg(target_arch = "x86_64")]
    {
        ostd::arch::read_tsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Single-writer OSTD owner of one portable CSER engine and its journal.
///
/// Construction alone does not publish the runtime. Production bootstrap must
/// install exactly one recovered instance before opening ingress.
#[derive(Debug)]
pub(crate) struct OstdCserRuntime<P> {
    state: Mutex<RuntimeState<P>>,
    serialization_telemetry: RuntimeSerializationTelemetry,
}

impl<P> OstdCserRuntime<P> {
    /// Wraps an already-created engine and its transition durability provider
    /// without activating any kernel ingress.
    ///
    /// Reply and DMA adapters must share this owner after the production
    /// cutover. Domain-specific physical custody lives outside the core, while
    /// every semantic transition and durability decision is serialized here.
    pub(crate) const fn from_engine(engine: Engine, persistence: P) -> Self {
        Self {
            state: Mutex::new(RuntimeState {
                engine,
                persistence,
            }),
            serialization_telemetry: RuntimeSerializationTelemetry::new(),
        }
    }

    /// Replays a journal under a mandatory trusted anchor.
    ///
    /// The caller retains responsibility for obtaining `bytes` and the anchor
    /// from independent persistent providers.  A returned torn-tail boundary
    /// is not permission to publish the runtime.
    pub(crate) fn recover(
        catalog: DomainCatalog,
        limits: CoreLimits,
        anchor: RecoveryAnchor,
        bytes: &[u8],
        persistence: P,
    ) -> Result<(Self, OstdRecoveryBoundary), CoreError> {
        let report = Engine::recover(catalog, limits, anchor, bytes)?;
        let boundary = OstdRecoveryBoundary {
            acknowledged_revision: report.acknowledged_revision(),
            acknowledged_head: report.acknowledged_head(),
            journal_repair: report.journal_repair(),
        };
        Ok((
            Self::from_engine(report.into_engine(), persistence),
            boundary,
        ))
    }

    /// Runs a read-only operation under the authoritative writer lock.
    pub(crate) fn observe<R>(&self, operation: impl FnOnce(&Engine) -> R) -> R {
        let state = self.state.lock();
        operation(&state.engine)
    }

    /// Runs a read-only durability-provider observation under the same owner
    /// lock as the engine.
    ///
    /// This is for diagnostics and provider lifecycle checks only. It cannot
    /// append journal bytes or advance a trusted anchor.
    pub(crate) fn observe_persistence<R>(&self, operation: impl FnOnce(&P) -> R) -> R {
        let state = self.state.lock();
        operation(&state.persistence)
    }

    /// Enables or disables default-off writer-serialization timing.
    ///
    /// Toggling clears previous samples.  This is a measurement-only control:
    /// it never participates in transition ordering or durable recovery.
    pub(crate) fn set_serialization_timing(&self, enabled: bool) {
        // Serialize an epoch reset with transaction sampling. A transaction
        // records before dropping this same mutex, so a completed toggle can
        // neither inherit a late sample from the preceding epoch nor clear a
        // partially published sample from the next one.
        let _state = self.state.lock();
        self.serialization_telemetry.set_enabled(enabled);
    }

    /// Returns the aggregate durable-transition lock samples collected since
    /// the last timing toggle.
    pub(crate) fn serialization_metrics(&self) -> RuntimeSerializationMetrics {
        let _state = self.state.lock();
        self.serialization_telemetry.snapshot()
    }
}

impl<P: TransitionDurability> OstdCserRuntime<P> {
    /// Executes one core transition and its exact durable append/barrier.
    ///
    /// This method may block and therefore is manager/task-context only.  A
    /// persistence failure leaves the engine recovery-required exactly as
    /// specified by `cser-core`.
    pub(crate) fn transact<C>(&self, command: C) -> Result<TransitionReceipt, TxError<P::Error>>
    where
        C: Into<Command>,
    {
        let queued_at = self.serialization_telemetry.enabled().then(timing_cycles);
        let mut state = self.state.lock();
        // A toggle also owns `state`, so this second check establishes the
        // exact measurement epoch for the entire transaction below.
        let acquired_at = queued_at
            .filter(|_| self.serialization_telemetry.enabled())
            .map(|_| timing_cycles());
        let RuntimeState {
            engine,
            persistence,
        } = &mut *state;
        // Do not split candidate evaluation from persistence here.  The core's
        // candidate, append/readback, and anchor advance must stay under this
        // single owner until a revision-revalidated protocol proves otherwise.
        let result = engine.transact_durable(command, persistence);
        let lock_hold = acquired_at.map(|acquired_at| timing_cycles().saturating_sub(acquired_at));
        if let (Some(queued_at), Some(acquired_at), Some(lock_hold_cycles)) =
            (queued_at, acquired_at, lock_hold)
        {
            self.serialization_telemetry
                .record(acquired_at.saturating_sub(queued_at), lock_hold_cycles);
        }
        drop(state);
        result
    }
}

#[cfg(any(test, ktest))]
mod tests {
    use cser_core::{
        AGENT_OPERATION_COMPOSITE, BootGeneration, ChargeAccountId, CommandRequest,
        DeviceGeneration, EffectId, Freshness, JournalGeneration, JournalRecord, PrincipalId,
        PrincipalIncarnation, RegistryInstance, RootId, standard_catalog,
    };
    #[cfg(ktest)]
    use ostd::prelude::ktest;

    use super::*;

    #[derive(Default)]
    struct TestDurability;

    impl TransitionDurability for TestDurability {
        type Error = &'static str;

        fn persist_transition(
            &mut self,
            record: &JournalRecord,
            _resulting_freshness: Freshness,
        ) -> Result<(), Self::Error> {
            assert!(!record.bytes().is_empty());
            Ok(())
        }
    }

    fn runtime() -> OstdCserRuntime<TestDurability> {
        let freshness = Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            1,
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        )
        .unwrap();
        OstdCserRuntime::from_engine(
            Engine::new(standard_catalog(), CoreLimits::bounded_default(), freshness),
            TestDurability,
        )
    }

    fn create(effect_sequence: u64) -> CommandRequest {
        let root = RootId::new(1).unwrap();
        CommandRequest::CreateCompositeEffect {
            effect: EffectId::new(root, effect_sequence).unwrap(),
            origin: PrincipalIncarnation::new(PrincipalId::new(1).unwrap(), 1).unwrap(),
            binding_generation: 1,
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: ChargeAccountId::new(1).unwrap(),
        }
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn serialization_timing_is_default_off() {
        let runtime = runtime();
        runtime.transact(create(1)).unwrap();
        assert_eq!(
            runtime.serialization_metrics(),
            RuntimeSerializationMetrics::default()
        );
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn serialization_timing_samples_transaction_and_resets_on_toggle() {
        let runtime = runtime();
        runtime.set_serialization_timing(true);
        runtime.transact(create(1)).unwrap();
        let metrics = runtime.serialization_metrics();
        assert_eq!(metrics.transactions, 1);
        assert!(metrics.lock_wait_cycles >= metrics.max_lock_wait_cycles);
        assert!(metrics.lock_hold_cycles >= metrics.max_lock_hold_cycles);

        runtime.set_serialization_timing(false);
        assert_eq!(
            runtime.serialization_metrics(),
            RuntimeSerializationMetrics::default()
        );
        runtime.transact(create(2)).unwrap();
        assert_eq!(
            runtime.serialization_metrics(),
            RuntimeSerializationMetrics::default()
        );
    }
}
