// SPDX-License-Identifier: MPL-2.0

//! Production OSTD ownership boundary for the portable CSER core.
//!
//! This module owns no global instance. The production bootstrap constructs one
//! recovered owner and shares it with every ingress adapter that may mutate the
//! engine.
//!
//! Transactions enter through one OSTD sleepable commit gate and then acquire
//! the engine and persistence mutexes in that order across the journal append
//! and durability barrier required by [`Engine::transact_durable`].
//! Consequently callers must enter through a manager/task context which may
//! block. IRQ handlers, atomic callbacks, and code already holding a spin lock
//! may only enqueue work for that owner; they must never call
//! [`OstdCserRuntime::transact`] directly.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use cser_core::{
    CatalogSet, Command, CoordinatedPersistence, CoordinatedPersistenceError, CoreError,
    CoreLimits, Digest, Engine, JournalRepair, RecoveryAnchor, StreamingJournalBackend,
    TransitionDurability, TransitionReceipt, TrustedAnchorBackend, TxError,
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

/// Failure while minting or staging/anchoring a durable whole-state
/// checkpoint.
#[derive(Debug)]
pub(crate) enum RuntimeCheckpointError<E> {
    /// The checkpoint transition itself did not become authoritatively durable.
    Transition(TxError<E>),
}

type CoordinatedPersistenceFailure<J, A> = CoordinatedPersistenceError<
    <J as StreamingJournalBackend>::Error,
    <A as TrustedAnchorBackend>::Error,
>;

type RuntimeCheckpointResult<J, A> =
    Result<TransitionReceipt, RuntimeCheckpointError<CoordinatedPersistenceFailure<J, A>>>;

type RuntimeCheckpointObservationResult<J, A, R> =
    Result<(TransitionReceipt, R, R), RuntimeCheckpointError<CoordinatedPersistenceFailure<J, A>>>;

/// Snapshot of optional timing taken around the runtime's commit gate and
/// engine writer mutex.
///
/// The cycle fields are intentionally an aggregate rather than a latency
/// promise: sampling is off by default, and a TSC sample is useful for the
/// single-CPU QEMU measurement profile, not as a portable wall-clock.  A
/// concurrent caller may update the counters while this snapshot is read.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RuntimeSerializationMetrics {
    /// Number of durable transitions sampled while timing was enabled.
    pub(crate) transactions: u64,
    /// Sum of cycles spent waiting to acquire the engine writer mutex.
    ///
    /// This intentionally excludes time spent waiting for the commit gate.
    pub(crate) lock_wait_cycles: u64,
    /// Largest single sampled engine writer-mutex wait.
    pub(crate) max_lock_wait_cycles: u64,
    /// Sum of cycles spent holding the engine writer mutex, including
    /// durability I/O for ordinary transitions.
    pub(crate) lock_hold_cycles: u64,
    /// Largest single sampled engine writer-mutex hold.
    pub(crate) max_lock_hold_cycles: u64,
    /// Sum of cycles spent waiting for the commit gate.  This is business
    /// serialization, not writer-mutex pause.
    pub(crate) commit_gate_wait_cycles: u64,
    /// Largest single sampled commit-gate wait.
    pub(crate) max_commit_gate_wait_cycles: u64,
    /// Number of staged checkpoints sampled.
    pub(crate) checkpoints: u64,
    /// Sum of cycles spent waiting for the engine writer mutex during
    /// checkpoint snapshot/prepare/take/put phases.
    pub(crate) checkpoint_lock_wait_cycles: u64,
    /// Largest single checkpoint engine writer-mutex wait.
    pub(crate) max_checkpoint_lock_wait_cycles: u64,
    /// Sum of cycles spent holding the engine writer mutex during checkpoint
    /// snapshot/prepare/take/put phases.  Checkpoint encoding, staging, and
    /// trusted-anchor I/O are excluded.
    pub(crate) checkpoint_lock_hold_cycles: u64,
    /// Largest single checkpoint engine writer-mutex hold.
    pub(crate) max_checkpoint_lock_hold_cycles: u64,
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
    commit_gate_wait_cycles: AtomicU64,
    max_commit_gate_wait_cycles: AtomicU64,
    checkpoints: AtomicU64,
    checkpoint_lock_wait_cycles: AtomicU64,
    max_checkpoint_lock_wait_cycles: AtomicU64,
    checkpoint_lock_hold_cycles: AtomicU64,
    max_checkpoint_lock_hold_cycles: AtomicU64,
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
            commit_gate_wait_cycles: AtomicU64::new(0),
            max_commit_gate_wait_cycles: AtomicU64::new(0),
            checkpoints: AtomicU64::new(0),
            checkpoint_lock_wait_cycles: AtomicU64::new(0),
            max_checkpoint_lock_wait_cycles: AtomicU64::new(0),
            checkpoint_lock_hold_cycles: AtomicU64::new(0),
            max_checkpoint_lock_hold_cycles: AtomicU64::new(0),
        }
    }

    fn set_enabled(&self, enabled: bool) {
        self.transactions.store(0, Ordering::Relaxed);
        self.lock_wait_cycles.store(0, Ordering::Relaxed);
        self.max_lock_wait_cycles.store(0, Ordering::Relaxed);
        self.lock_hold_cycles.store(0, Ordering::Relaxed);
        self.max_lock_hold_cycles.store(0, Ordering::Relaxed);
        self.commit_gate_wait_cycles.store(0, Ordering::Relaxed);
        self.max_commit_gate_wait_cycles.store(0, Ordering::Relaxed);
        self.checkpoints.store(0, Ordering::Relaxed);
        self.checkpoint_lock_wait_cycles.store(0, Ordering::Relaxed);
        self.max_checkpoint_lock_wait_cycles
            .store(0, Ordering::Relaxed);
        self.checkpoint_lock_hold_cycles.store(0, Ordering::Relaxed);
        self.max_checkpoint_lock_hold_cycles
            .store(0, Ordering::Relaxed);
        self.enabled.store(enabled, Ordering::Release);
    }

    fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    fn record(&self, commit_gate_wait_cycles: u64, lock_wait_cycles: u64, lock_hold_cycles: u64) {
        saturating_atomic_add(&self.transactions, 1);
        saturating_atomic_add(&self.commit_gate_wait_cycles, commit_gate_wait_cycles);
        self.max_commit_gate_wait_cycles
            .fetch_max(commit_gate_wait_cycles, Ordering::Relaxed);
        saturating_atomic_add(&self.lock_wait_cycles, lock_wait_cycles);
        self.max_lock_wait_cycles
            .fetch_max(lock_wait_cycles, Ordering::Relaxed);
        saturating_atomic_add(&self.lock_hold_cycles, lock_hold_cycles);
        self.max_lock_hold_cycles
            .fetch_max(lock_hold_cycles, Ordering::Relaxed);
    }

    fn record_checkpoint(
        &self,
        commit_gate_wait_cycles: u64,
        lock_wait_cycles: u64,
        lock_hold_cycles: u64,
    ) {
        saturating_atomic_add(&self.checkpoints, 1);
        saturating_atomic_add(&self.commit_gate_wait_cycles, commit_gate_wait_cycles);
        self.max_commit_gate_wait_cycles
            .fetch_max(commit_gate_wait_cycles, Ordering::Relaxed);
        saturating_atomic_add(&self.checkpoint_lock_wait_cycles, lock_wait_cycles);
        self.max_checkpoint_lock_wait_cycles
            .fetch_max(lock_wait_cycles, Ordering::Relaxed);
        saturating_atomic_add(&self.checkpoint_lock_hold_cycles, lock_hold_cycles);
        self.max_checkpoint_lock_hold_cycles
            .fetch_max(lock_hold_cycles, Ordering::Relaxed);
    }

    fn snapshot(&self) -> RuntimeSerializationMetrics {
        RuntimeSerializationMetrics {
            transactions: self.transactions.load(Ordering::Relaxed),
            lock_wait_cycles: self.lock_wait_cycles.load(Ordering::Relaxed),
            max_lock_wait_cycles: self.max_lock_wait_cycles.load(Ordering::Relaxed),
            lock_hold_cycles: self.lock_hold_cycles.load(Ordering::Relaxed),
            max_lock_hold_cycles: self.max_lock_hold_cycles.load(Ordering::Relaxed),
            commit_gate_wait_cycles: self.commit_gate_wait_cycles.load(Ordering::Relaxed),
            max_commit_gate_wait_cycles: self.max_commit_gate_wait_cycles.load(Ordering::Relaxed),
            checkpoints: self.checkpoints.load(Ordering::Relaxed),
            checkpoint_lock_wait_cycles: self.checkpoint_lock_wait_cycles.load(Ordering::Relaxed),
            max_checkpoint_lock_wait_cycles: self
                .max_checkpoint_lock_wait_cycles
                .load(Ordering::Relaxed),
            checkpoint_lock_hold_cycles: self.checkpoint_lock_hold_cycles.load(Ordering::Relaxed),
            max_checkpoint_lock_hold_cycles: self
                .max_checkpoint_lock_hold_cycles
                .load(Ordering::Relaxed),
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
    /// Serializes the whole authority sequence.  It is deliberately held
    /// while checkpoint plans are encoded, but no engine writer mutex is held
    /// during that O(N) work.
    commit_gate: Mutex<()>,
    /// Semantic state.  The only mutable engine lock in this owner.  The
    /// `Option` permits a checkpoint's trusted-anchor call to run against the
    /// exact engine while this writer mutex is free; `commit_gate` prevents
    /// any other authority operation from observing the temporary vacancy.
    engine: Mutex<Option<Engine>>,
    /// Durable provider state.  Lock order is always commit_gate -> engine ->
    /// persistence for mutating paths; read-only observations take only the
    /// lock they observe.
    persistence: Mutex<P>,
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
            commit_gate: Mutex::new(()),
            engine: Mutex::new(Some(engine)),
            persistence: Mutex::new(persistence),
            serialization_telemetry: RuntimeSerializationTelemetry::new(),
        }
    }

    /// Replays a journal under a mandatory trusted anchor.
    ///
    /// The caller retains responsibility for obtaining `bytes` and the anchor
    /// from independent persistent providers.  A returned torn-tail boundary
    /// is not permission to publish the runtime.
    pub(crate) fn recover(
        catalogs: CatalogSet,
        limits: CoreLimits,
        anchor: RecoveryAnchor,
        bytes: &[u8],
        persistence: P,
    ) -> Result<(Self, OstdRecoveryBoundary), CoreError> {
        let report = Engine::recover(catalogs, limits, anchor, bytes)?;
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
        let _commit_gate = self.commit_gate.lock();
        let engine = self.engine.lock();
        operation(
            engine
                .as_ref()
                .expect("CSER runtime engine slot is occupied outside checkpoint publication"),
        )
    }

    /// Returns one provider-generation projection under the authoritative
    /// writer lock. This is a read-only query; lifecycle transitions continue
    /// to require the trusted production owner path.
    pub(crate) fn provider_generation_projection(
        &self,
        coordinate: cser_core::ProviderCoordinate,
    ) -> Option<cser_core::ProviderGenerationProjection> {
        self.observe(|engine| engine.provider_generation_projection(coordinate))
    }

    /// Runs a read-only durability-provider observation under the same owner
    /// lock as the engine.
    ///
    /// This is for diagnostics and provider lifecycle checks only. It cannot
    /// append journal bytes or advance a trusted anchor.
    pub(crate) fn observe_persistence<R>(&self, operation: impl FnOnce(&P) -> R) -> R {
        let _commit_gate = self.commit_gate.lock();
        let persistence = self.persistence.lock();
        operation(&persistence)
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
        let _commit_gate = self.commit_gate.lock();
        self.serialization_telemetry.set_enabled(enabled);
    }

    /// Returns the aggregate durable-transition lock samples collected since
    /// the last timing toggle.
    pub(crate) fn serialization_metrics(&self) -> RuntimeSerializationMetrics {
        let _commit_gate = self.commit_gate.lock();
        self.serialization_telemetry.snapshot()
    }

    /// Executes a read-only engine operation while measuring only the writer
    /// mutex wait and hold intervals.  The commit gate must be held by the
    /// caller for authority-sensitive paths, which is true for all current
    /// callers in this module.
    fn with_engine<R>(
        &self,
        measure: bool,
        operation: impl FnOnce(&Engine) -> R,
    ) -> (R, EngineLockSample) {
        let lock_queued_at = measure.then(timing_cycles);
        let engine = self.engine.lock();
        let lock_acquired_at = measure.then(timing_cycles);
        let result = operation(
            engine
                .as_ref()
                .expect("CSER runtime engine slot is occupied outside checkpoint publication"),
        );
        // The hold sample ends immediately before dropping the guard.  In
        // particular, it does not include lock acquisition or the drop itself.
        let lock_released_at = measure.then(timing_cycles);
        drop(engine);
        (
            result,
            EngineLockSample::from_timestamps(lock_queued_at, lock_acquired_at, lock_released_at),
        )
    }

    /// Executes a mutable engine operation while measuring only its writer
    /// mutex interval.  Checkpoint snapshot/prepare use this helper; the
    /// O(N) plan and encoding work are intentionally performed after the
    /// helper returns.
    fn with_engine_mut<R>(
        &self,
        measure: bool,
        operation: impl FnOnce(&mut Engine) -> R,
    ) -> (R, EngineLockSample) {
        let lock_queued_at = measure.then(timing_cycles);
        let mut engine = self.engine.lock();
        let lock_acquired_at = measure.then(timing_cycles);
        let result = operation(
            engine
                .as_mut()
                .expect("CSER runtime engine slot is occupied outside checkpoint publication"),
        );
        // See `with_engine`: this timestamp is taken while the guard is still
        // held and immediately before it is released.
        let lock_released_at = measure.then(timing_cycles);
        drop(engine);
        (
            result,
            EngineLockSample::from_timestamps(lock_queued_at, lock_acquired_at, lock_released_at),
        )
    }

    /// Detaches the unique engine for the final checkpoint publication phase.
    /// The caller must hold `commit_gate`; the returned guard restores the
    /// exact engine on every return path, including anchor errors and panic
    /// unwinding.  The writer mutex is held only for the take operation.
    fn detach_engine(&self, measure: bool) -> (DetachedEngine<'_, P>, EngineLockSample) {
        let lock_queued_at = measure.then(timing_cycles);
        let mut engine_slot = self.engine.lock();
        let lock_acquired_at = measure.then(timing_cycles);
        let engine = engine_slot
            .take()
            .expect("CSER runtime engine slot is occupied outside checkpoint publication");
        let lock_released_at = measure.then(timing_cycles);
        drop(engine_slot);
        (
            DetachedEngine {
                runtime: self,
                engine: Some(engine),
                measure,
            },
            EngineLockSample::from_timestamps(lock_queued_at, lock_acquired_at, lock_released_at),
        )
    }
}

/// One measured engine writer-mutex interval.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct EngineLockSample {
    wait_cycles: u64,
    hold_cycles: u64,
}

impl EngineLockSample {
    fn from_timestamps(
        queued_at: Option<u64>,
        acquired_at: Option<u64>,
        released_at: Option<u64>,
    ) -> Self {
        match (queued_at, acquired_at, released_at) {
            (Some(queued_at), Some(acquired_at), Some(released_at)) => Self {
                wait_cycles: acquired_at.saturating_sub(queued_at),
                hold_cycles: released_at.saturating_sub(acquired_at),
            },
            _ => Self::default(),
        }
    }
}

/// A temporarily detached, still-authoritative engine.
///
/// The checkpoint gate remains held while this value exists.  Its `Drop`
/// implementation is deliberately fail-closed: if an unexpected duplicate
/// engine is found in the slot, it panics rather than silently replacing a
/// different authority instance.  OSTD mutex locking is non-fallible, so this
/// also covers anchor errors and panic unwinding without losing the latched
/// engine.  A no-std panic that aborts the kernel cannot run any destructor;
/// that path is intentionally fail-stop rather than an attempted recovery.
struct DetachedEngine<'a, P> {
    runtime: &'a OstdCserRuntime<P>,
    engine: Option<Engine>,
    measure: bool,
}

impl<P> DetachedEngine<'_, P> {
    fn engine_mut(&mut self) -> &mut Engine {
        self.engine
            .as_mut()
            .expect("detached CSER engine was already restored")
    }

    fn restore(&mut self) -> EngineLockSample {
        let lock_queued_at = self.measure.then(timing_cycles);
        let mut engine_slot = self.runtime.engine.lock();
        let lock_acquired_at = self.measure.then(timing_cycles);
        assert!(
            engine_slot.is_none(),
            "CSER runtime engine slot changed while checkpoint engine was detached"
        );
        let engine = self
            .engine
            .take()
            .expect("detached CSER engine was already restored");
        *engine_slot = Some(engine);
        let lock_released_at = self.measure.then(timing_cycles);
        drop(engine_slot);
        EngineLockSample::from_timestamps(lock_queued_at, lock_acquired_at, lock_released_at)
    }
}

impl<P> Drop for DetachedEngine<'_, P> {
    fn drop(&mut self) {
        if self.engine.is_some() {
            // The caller holds `commit_gate`, so this cannot race an ordinary
            // operation.  Metrics are intentionally not emitted from Drop:
            // panic/error recovery must not manufacture a completed sample.
            let _ = self.restore();
        }
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
        let _commit_gate = self.commit_gate.lock();
        // A toggle also owns `commit_gate`, so this second check establishes the
        // exact measurement epoch for the entire transaction below.
        let gate_acquired_at = queued_at
            .filter(|_| self.serialization_telemetry.enabled())
            .map(|_| timing_cycles());
        let engine_lock_queued_at = gate_acquired_at.map(|_| timing_cycles());
        let mut engine_slot = self.engine.lock();
        let engine_acquired_at = engine_lock_queued_at.map(|_| timing_cycles());
        let engine = engine_slot
            .as_mut()
            .expect("CSER runtime engine slot is occupied outside checkpoint publication");
        let mut persistence = self.persistence.lock();
        // Do not split candidate evaluation from persistence here.  The core's
        // candidate, append/readback, and anchor advance must stay under this
        // single owner until a revision-revalidated protocol proves otherwise.
        let result = engine.transact_durable(command, &mut *persistence);
        if let (Some(queued_at), Some(gate_acquired_at), Some(engine_acquired_at)) =
            (queued_at, gate_acquired_at, engine_acquired_at)
        {
            let now = timing_cycles();
            self.serialization_telemetry.record(
                gate_acquired_at.saturating_sub(queued_at),
                engine_acquired_at.saturating_sub(engine_lock_queued_at.unwrap_or(now)),
                now.saturating_sub(engine_acquired_at),
            );
        }
        result
    }
}

impl<J, A> OstdCserRuntime<CoordinatedPersistence<J, A>>
where
    J: StreamingJournalBackend,
    A: TrustedAnchorBackend,
{
    /// Mints, stages, anchors, and publishes a compact whole-state checkpoint.
    /// The commit gate is held for the whole authority sequence, but snapshot
    /// capture, plan construction, and journal staging do not hold the engine
    /// writer mutex.
    ///
    /// This method owns the complete sequence under the same authoritative
    /// gate.  A staging/anchor failure latches the coordinator
    /// recovery-required; callers must drop and recover this runtime before
    /// another mutation.
    pub(crate) fn compact_checkpoint(&self) -> RuntimeCheckpointResult<J, A> {
        let gate_queued_at = self.serialization_telemetry.enabled().then(timing_cycles);
        let _commit_gate = self.commit_gate.lock();
        let commit_gate_wait_cycles = gate_queued_at
            .filter(|_| self.serialization_telemetry.enabled())
            .map(|queued_at| timing_cycles().saturating_sub(queued_at))
            .unwrap_or(0);
        let measure_engine_lock = self.serialization_telemetry.enabled();
        let mut engine_lock_wait_cycles: u64 = 0;
        let mut engine_lock_hold_cycles: u64 = 0;
        let (snapshot, sample) = self.with_engine(measure_engine_lock, |engine| {
            engine
                .checkpoint_snapshot()
                .map_err(|error| RuntimeCheckpointError::Transition(TxError::Core(error)))
        });
        engine_lock_wait_cycles = engine_lock_wait_cycles.saturating_add(sample.wait_cycles);
        engine_lock_hold_cycles = engine_lock_hold_cycles.saturating_add(sample.hold_cycles);
        let snapshot = snapshot?;
        // Counting and hashing are intentionally outside the engine writer
        // mutex.  The commit gate remains held so no ordinary transition can
        // invalidate the immutable roots before checkpoint_prepare.
        let plan = snapshot
            .prepare_plan()
            .map_err(|error| RuntimeCheckpointError::Transition(TxError::Core(error)))?;
        let (prepared, sample) = self.with_engine_mut(measure_engine_lock, |engine| {
            engine
                .checkpoint_prepare(plan)
                .map_err(|error| RuntimeCheckpointError::Transition(TxError::Core(error)))
        });
        engine_lock_wait_cycles = engine_lock_wait_cycles.saturating_add(sample.wait_cycles);
        engine_lock_hold_cycles = engine_lock_hold_cycles.saturating_add(sample.hold_cycles);
        let prepared = prepared?;
        // This consumes the raw prepared value only after staging has
        // succeeded.  A stage error leaves the engine latch armed.
        let durable = {
            let mut persistence = self.persistence.lock();
            prepared
                .persist_checkpoint(&mut *persistence)
                .map_err(RuntimeCheckpointError::Transition)?
        };
        // `checkpoint_publish` owns the opaque anchor token and its
        // assignment-only suffix.  Detach the exact Engine under the short
        // writer mutex, then keep only the commit gate while Core performs
        // trusted-anchor I/O.  `DetachedEngine` restores the latched engine
        // even when anchor publication returns an error or unwinds.
        let (mut detached, sample) = self.detach_engine(measure_engine_lock);
        engine_lock_wait_cycles = engine_lock_wait_cycles.saturating_add(sample.wait_cycles);
        engine_lock_hold_cycles = engine_lock_hold_cycles.saturating_add(sample.hold_cycles);
        let publish_result = {
            let mut persistence = self.persistence.lock();
            detached
                .engine_mut()
                .checkpoint_publish(durable, &mut *persistence)
        };
        let sample = detached.restore();
        engine_lock_wait_cycles = engine_lock_wait_cycles.saturating_add(sample.wait_cycles);
        engine_lock_hold_cycles = engine_lock_hold_cycles.saturating_add(sample.hold_cycles);
        let receipt = publish_result.map_err(RuntimeCheckpointError::Transition)?;
        if measure_engine_lock {
            self.serialization_telemetry.record_checkpoint(
                commit_gate_wait_cycles,
                engine_lock_wait_cycles,
                engine_lock_hold_cycles,
            );
        }
        Ok(receipt)
    }

    /// Compacts while copying one bounded, read-only journal observation on
    /// both sides of staging. Both copies are released from the persistence
    /// lock before the trusted-anchor boundary; the post-anchor suffix remains
    /// callback-free and cannot retain a journal-sized owner.
    pub(crate) fn compact_checkpoint_observed<R: Copy>(
        &self,
        observe: impl Fn(&J) -> R,
    ) -> RuntimeCheckpointObservationResult<J, A, R> {
        let gate_queued_at = self.serialization_telemetry.enabled().then(timing_cycles);
        let _commit_gate = self.commit_gate.lock();
        let commit_gate_wait_cycles = gate_queued_at
            .filter(|_| self.serialization_telemetry.enabled())
            .map(|queued_at| timing_cycles().saturating_sub(queued_at))
            .unwrap_or(0);
        let measure_engine_lock = self.serialization_telemetry.enabled();
        let mut engine_lock_wait_cycles: u64 = 0;
        let mut engine_lock_hold_cycles: u64 = 0;
        let before = {
            let persistence = self.persistence.lock();
            observe(persistence.journal())
        };
        let (snapshot, sample) = self.with_engine(measure_engine_lock, |engine| {
            engine
                .checkpoint_snapshot()
                .map_err(|error| RuntimeCheckpointError::Transition(TxError::Core(error)))
        });
        engine_lock_wait_cycles = engine_lock_wait_cycles.saturating_add(sample.wait_cycles);
        engine_lock_hold_cycles = engine_lock_hold_cycles.saturating_add(sample.hold_cycles);
        let snapshot = snapshot?;
        let plan = snapshot
            .prepare_plan()
            .map_err(|error| RuntimeCheckpointError::Transition(TxError::Core(error)))?;
        let (prepared, sample) = self.with_engine_mut(measure_engine_lock, |engine| {
            engine
                .checkpoint_prepare(plan)
                .map_err(|error| RuntimeCheckpointError::Transition(TxError::Core(error)))
        });
        engine_lock_wait_cycles = engine_lock_wait_cycles.saturating_add(sample.wait_cycles);
        engine_lock_hold_cycles = engine_lock_hold_cycles.saturating_add(sample.hold_cycles);
        let prepared = prepared?;
        let durable = {
            let mut persistence = self.persistence.lock();
            prepared
                .persist_checkpoint(&mut *persistence)
                .map_err(RuntimeCheckpointError::Transition)?
        };
        // Staging has selected the physical image, but the trusted anchor has
        // not advanced yet.  A failing observation therefore remains safely
        // before the anchor boundary and leaves the Core latch armed.
        let after = {
            let persistence = self.persistence.lock();
            observe(persistence.journal())
        };
        let (mut detached, sample) = self.detach_engine(measure_engine_lock);
        engine_lock_wait_cycles = engine_lock_wait_cycles.saturating_add(sample.wait_cycles);
        engine_lock_hold_cycles = engine_lock_hold_cycles.saturating_add(sample.hold_cycles);
        let publish_result = {
            let mut persistence = self.persistence.lock();
            detached
                .engine_mut()
                .checkpoint_publish(durable, &mut *persistence)
        };
        let sample = detached.restore();
        engine_lock_wait_cycles = engine_lock_wait_cycles.saturating_add(sample.wait_cycles);
        engine_lock_hold_cycles = engine_lock_hold_cycles.saturating_add(sample.hold_cycles);
        let receipt = publish_result.map_err(RuntimeCheckpointError::Transition)?;
        if measure_engine_lock {
            self.serialization_telemetry.record_checkpoint(
                commit_gate_wait_cycles,
                engine_lock_wait_cycles,
                engine_lock_hold_cycles,
            );
        }
        Ok((receipt, before, after))
    }
}

#[cfg(any(test, ktest))]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec;
    use core::sync::atomic::{AtomicU64, Ordering};

    use cser_core::{
        AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration,
        ChargeAccountId, CommandRequest, ComponentProviderBinding, CoordinatedPersistence,
        DeviceGeneration, Digest, EffectId, ExecutorCoordinate, ExecutorGeneration, ExecutorId,
        Freshness, JournalGeneration, JournalRecord, OperationId, ProviderCoordinate,
        ProviderGeneration, ProviderId, RecoveryBinding, RecoveryLease, RecoveryProfile,
        RegistryInstance, TrustedAnchorBackend, TrustedAnchorSnapshot, VerifierBinding,
        VerifierGeneration, WorldId, standard_catalog,
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
            _resulting_projection: Digest,
        ) -> Result<(), Self::Error> {
            assert!(!record.bytes().is_empty());
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StreamingTestError {
        Anchor,
    }

    struct StreamingTestJournal {
        stages: Arc<AtomicU64>,
    }

    impl cser_core::DurableJournalBackend for StreamingTestJournal {
        type Error = StreamingTestError;

        fn append_and_sync(&mut self, _record: &JournalRecord) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl StreamingJournalBackend for StreamingTestJournal {
        type Error = StreamingTestError;

        fn stage_checkpoint(
            &mut self,
            plan: &cser_core::CheckpointRecordPlan,
        ) -> Result<(), StreamingTestError> {
            assert!(plan.record_len() > plan.state_len());
            self.stages.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct StreamingTestAnchor {
        committed: TrustedAnchorSnapshot,
    }

    impl TrustedAnchorBackend for StreamingTestAnchor {
        type Error = StreamingTestError;

        fn reserve_recovery_epoch(
            &mut self,
            _binding: RecoveryBinding,
            _observed_device: DeviceGeneration,
        ) -> Result<RecoveryLease, Self::Error> {
            Err(StreamingTestError::Anchor)
        }

        fn compare_and_advance(
            &mut self,
            expected: TrustedAnchorSnapshot,
            replacement: TrustedAnchorSnapshot,
        ) -> Result<(), Self::Error> {
            if expected != self.committed {
                return Err(StreamingTestError::Anchor);
            }
            self.committed = replacement;
            Ok(())
        }
    }

    fn runtime() -> OstdCserRuntime<TestDurability> {
        let world = WorldId::new(1).unwrap();
        let catalog = standard_catalog();
        let catalogs = cser_core::CatalogSet::new(core::slice::from_ref(&catalog)).unwrap();
        let freshness = Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        );
        let provider = ProviderCoordinate::new(
            world,
            ProviderId::new(1).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        let verifier_generation = VerifierGeneration::new(1).unwrap();
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
                .unwrap()
            })
            .collect();
        let mut engine = Engine::new(world, catalogs, CoreLimits::bounded_default(), freshness);
        engine
            .transact(
                CommandRequest::RegisterProviderGeneration {
                    coordinate: provider,
                    catalog_digest: catalog.digest(),
                    verifier_bindings,
                },
                |_| Ok::<(), &'static str>(()),
            )
            .unwrap();
        OstdCserRuntime::from_engine(engine, TestDurability)
    }

    fn create(effect_sequence: u64) -> CommandRequest {
        let operation = OperationId::new(1).unwrap();
        let provider = ProviderCoordinate::new(
            WorldId::new(1).unwrap(),
            ProviderId::new(1).unwrap(),
            ProviderGeneration::new(1).unwrap(),
        );
        CommandRequest::AdmitScopedCompositeEffect {
            effect: EffectId::new(operation, effect_sequence).unwrap(),
            origin: ExecutorCoordinate::new(
                ExecutorId::new(1).unwrap(),
                ExecutorGeneration::new(1).unwrap(),
            ),
            kind: AGENT_OPERATION_COMPOSITE,
            charge_account: ChargeAccountId::new(1).unwrap(),
            bindings: vec![
                ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, provider),
                ComponentProviderBinding::new(AGENT_COMPONENT_DMA, provider),
            ],
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
        assert!(metrics.commit_gate_wait_cycles >= metrics.max_commit_gate_wait_cycles);

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

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn detached_engine_drop_restores_the_same_authority_slot() {
        let runtime = runtime();
        let expected = runtime.observe(|engine| (engine.revision(), engine.head()));
        {
            let _commit_gate = runtime.commit_gate.lock();
            let (mut detached, sample) = runtime.detach_engine(false);
            assert_eq!(sample, EngineLockSample::default());
            let observed = {
                let engine = detached.engine_mut();
                (engine.revision(), engine.head())
            };
            assert_eq!(observed, expected);
            // Dropping without an explicit restore exercises the same RAII
            // path used by anchor errors and unwinding.
        }
        runtime.observe(|engine| {
            assert_eq!(engine.revision(), expected.0);
            assert_eq!(engine.head(), expected.1);
        });
    }

    #[cfg_attr(ktest, ktest)]
    #[cfg_attr(test, test)]
    fn runtime_publishes_only_the_anchored_checkpoint_under_its_gate() {
        let catalog = standard_catalog();
        let catalogs = cser_core::CatalogSet::new(core::slice::from_ref(&catalog)).unwrap();
        let freshness = Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        );
        let next = Freshness::new(
            BootGeneration::new(2).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(2).unwrap(),
        );
        let binding = RecoveryBinding::new(
            RecoveryProfile::current(),
            WorldId::new(1).unwrap(),
            catalog.digest(),
            RegistryInstance::new(1).unwrap(),
        )
        .unwrap();
        let engine = Engine::new(
            WorldId::new(1).unwrap(),
            catalogs,
            CoreLimits::bounded_default(),
            freshness,
        );
        let committed = TrustedAnchorSnapshot::from_trusted_backend(
            binding,
            freshness,
            0,
            cser_core::Digest::ZERO,
            engine.projection_digest(),
        )
        .unwrap();
        let lease = RecoveryLease::from_trusted_backend(committed, next).unwrap();
        let stages = Arc::new(AtomicU64::new(0));
        let persistence = CoordinatedPersistence::from_recovery_lease(
            StreamingTestJournal {
                stages: stages.clone(),
            },
            StreamingTestAnchor { committed },
            &lease,
        );
        let runtime = OstdCserRuntime::from_engine(engine, persistence);

        runtime.set_serialization_timing(true);
        let receipt = runtime.compact_checkpoint().expect("runtime checkpoint");
        assert_eq!(stages.load(Ordering::Relaxed), 1);
        let metrics = runtime.serialization_metrics();
        assert_eq!(metrics.checkpoints, 1);
        assert!(metrics.commit_gate_wait_cycles >= metrics.max_commit_gate_wait_cycles);
        assert!(metrics.checkpoint_lock_wait_cycles >= metrics.max_checkpoint_lock_wait_cycles);
        assert!(metrics.checkpoint_lock_hold_cycles >= metrics.max_checkpoint_lock_hold_cycles);
        runtime.observe_persistence(|persistence| {
            assert!(!persistence.recovery_required());
            assert_eq!(persistence.committed().revision(), receipt.revision());
            assert_eq!(persistence.committed().head(), receipt.head());
        });
        runtime.observe(|engine| {
            assert_eq!(engine.revision(), receipt.revision());
            assert_eq!(engine.head(), receipt.head());
        });
    }
}
