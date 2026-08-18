//! Small host profile for the canonical streaming checkpoint protocol.
//!
//! The measured path is deliberately the same sequence a production embedding
//! uses:
//!
//! ```text
//! checkpoint_snapshot
//!   -> CheckpointSnapshot::prepare_plan (count + canonical hash)
//!   -> Engine::checkpoint_prepare
//!   -> PreparedCheckpoint::persist_checkpoint (stage + encode)
//!   -> Engine::checkpoint_publish (anchor + assignment-only publication)
//! ```
//!
//! The profile backend is a counting/discard sink.  It does not hide a
//! checkpoint-sized `Vec` behind `StreamingJournalBackend`; `staged_bytes` is
//! only the number of bytes supplied to the sink.  The separately captured
//! canonical record used by recovery is an explicitly source-owned fixture and
//! is not included in stage/encode allocations.
//!
//! The first recovery row uses the public positioned
//! `Engine::recover_from_source` entry point with a fixed 4 KiB scratch
//! buffer.  The source owns the fixture bytes; Core only receives positioned
//! reads and never gets a contiguous recovery slice.
//!
//! This is a measurement helper, not a benchmark gate.  Absolute timings are
//! observations only and are never used as CI assertions.  Set
//! `CSER_PROFILE_SIZES=4096` (or a comma-separated list) to select a larger
//! target.

use core::convert::Infallible;
use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration,
    CatalogSet, CheckpointRecordPlan, CheckpointWrite, CommandRequest, ComponentProviderBinding,
    CoordinatedPersistence, CoreLimits, DeviceGeneration, Digest, Engine, ExecutorCoordinate,
    ExecutorGeneration, ExecutorId, Freshness, JournalGeneration, JournalRecoverySource,
    OperationId, ProviderCoordinate, ProviderGeneration, ProviderId, RecoveryAnchor,
    RecoveryBinding, RecoveryLease, RecoveryProfile, RecoverySourceSnapshot, RegistryInstance,
    StreamingJournalBackend, TrustedAnchorBackend, TrustedAnchorSnapshot, VerifierBinding,
    VerifierGeneration, WorldId, standard_catalog,
};

const WORLD: u64 = 1;
const PROVIDER_BASE: u64 = 10_000;
const OPERATION_BASE: u64 = 20_000;
const ACTOR_BASE: u64 = 30_000;

const DEFAULT_SIZES: [usize; 3] = [1, 64, 512];
const WARMUPS: usize = 2;
const SAMPLES: usize = 7;

static ALLOCATION_CALLS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static SAMPLE_BASE_LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

fn retain_live_bytes(bytes: usize) {
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    let mut peak = PEAK_LIVE_BYTES.load(Ordering::Relaxed);
    while live > peak {
        match PEAK_LIVE_BYTES.compare_exchange_weak(
            peak,
            live,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => peak = observed,
        }
    }
}

fn live_bytes() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

fn peak_live_bytes() -> usize {
    PEAK_LIVE_BYTES.load(Ordering::Relaxed)
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOCATION_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            retain_live_bytes(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOCATION_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            retain_live_bytes(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let replacement = unsafe { System.realloc(pointer, layout, size) };
        if !replacement.is_null() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOCATION_BYTES.fetch_add(size, Ordering::Relaxed);
            if size >= layout.size() {
                retain_live_bytes(size - layout.size());
            } else {
                LIVE_BYTES.fetch_sub(layout.size() - size, Ordering::Relaxed);
            }
        }
        replacement
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct AllocationSample {
    calls: usize,
    bytes: usize,
    peak_live_bytes: usize,
}

fn reset_allocations() {
    ALLOCATION_CALLS.store(0, Ordering::Relaxed);
    ALLOCATION_BYTES.store(0, Ordering::Relaxed);
    let live = live_bytes();
    SAMPLE_BASE_LIVE_BYTES.store(live, Ordering::Relaxed);
    PEAK_LIVE_BYTES.store(live, Ordering::Relaxed);
}

fn allocations() -> AllocationSample {
    AllocationSample {
        calls: ALLOCATION_CALLS.load(Ordering::Relaxed),
        bytes: ALLOCATION_BYTES.load(Ordering::Relaxed),
        peak_live_bytes: PEAK_LIVE_BYTES
            .load(Ordering::Relaxed)
            .saturating_sub(SAMPLE_BASE_LIVE_BYTES.load(Ordering::Relaxed)),
    }
}

fn checked_live_sub(later: usize, earlier: usize, label: &str) -> usize {
    later
        .checked_sub(earlier)
        .unwrap_or_else(|| panic!("{label}: live-byte counter moved backwards"))
}

#[derive(Clone, Copy, Debug, Default)]
struct OwnershipSample {
    /// Bytes in the source journal fixture, not a copy made by the measured
    /// streaming backend.
    source_record_bytes: usize,
    /// Bytes in the source-owned canonical checkpoint fixture.
    source_checkpoint_bytes: usize,
    /// Bytes copied into a profile-owned journal record buffer.
    record_owned_copy_bytes: usize,
    /// Bytes copied into a profile-owned checkpoint buffer.
    checkpoint_owned_copy_bytes: usize,
    /// Bytes offered to the streaming backend's discard sink.
    staged_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct MemorySample {
    ownership: OwnershipSample,
    engine_retained_bytes: usize,
    /// Peak bytes owned by the measured Core operation, including the final
    /// retained Engine.  For an operation on an existing Engine this is the
    /// retained Engine plus the peak delta; for recovery it is the complete
    /// peak delta above the source/catalog baseline.
    core_peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct PhaseSample {
    nanos: u128,
    allocations: AllocationSample,
    memory: MemorySample,
    /// Time spent in the in-memory trusted-anchor implementation.  This is
    /// not storage I/O; it is reported only to make the publication boundary
    /// visible and to show that publication rows do not include anchor I/O.
    anchor_nanos: u128,
    anchor_allocations: AllocationSample,
    recovery_reads: usize,
    recovery_read_bytes: usize,
}

fn memory_for_existing_engine(
    ownership: OwnershipSample,
    base_live_bytes: usize,
    peak_live_bytes: usize,
    engine_retained_bytes: usize,
) -> MemorySample {
    let peak_delta_bytes = checked_live_sub(
        peak_live_bytes,
        base_live_bytes,
        "peak-live versus existing-engine baseline",
    );
    MemorySample {
        ownership,
        engine_retained_bytes,
        core_peak_bytes: engine_retained_bytes
            .checked_add(peak_delta_bytes)
            .expect("existing-engine peak bytes fit"),
    }
}

fn finish_existing_engine(
    fixture: StreamingFixture,
    ownership: OwnershipSample,
    base_live_bytes: usize,
    peak_live_bytes: usize,
) -> MemorySample {
    let StreamingFixture {
        engine,
        source_journal,
        catalog,
        limits: _,
        persistence,
    } = fixture;
    let engine_live_bytes = live_bytes();
    // Drop all profile persistence state before deriving the engine-owned
    // denominator.  The profile backend has no checkpoint-sized allocation,
    // but this ordering keeps that fact explicit if it changes later.
    drop(persistence);
    drop(engine);
    let after_drop_live_bytes = live_bytes();
    let engine_retained_bytes = checked_live_sub(
        engine_live_bytes,
        after_drop_live_bytes,
        "existing fixture engine drop",
    );
    let memory = memory_for_existing_engine(
        ownership,
        base_live_bytes,
        peak_live_bytes,
        engine_retained_bytes,
    );
    validate_memory_sample(memory);
    // These are source fixtures.  Their drops are outside the measured phase.
    drop(source_journal);
    drop(catalog);
    memory
}

fn finish_recovery_engine(
    input: &RecoveryInput,
    catalog: CatalogSet,
    engine: Engine,
    ownership: OwnershipSample,
    base_live_bytes: usize,
    peak_live_bytes: usize,
) -> MemorySample {
    let engine_live_bytes = live_bytes();
    drop(engine);
    let after_drop_live_bytes = live_bytes();
    let engine_retained_bytes = checked_live_sub(
        engine_live_bytes,
        after_drop_live_bytes,
        "recovery engine drop",
    );
    // `base_live_bytes` includes the source-owned bytes and catalog retained
    // by `input`, while `catalog` was consumed by the recovered Engine.  The
    // engine delta is therefore independent of the source representation.
    black_box((input.bytes.len(), catalog.digest()));
    let core_peak_bytes = checked_live_sub(
        peak_live_bytes,
        base_live_bytes,
        "recovery peak versus source/catalog baseline",
    );
    let memory = MemorySample {
        ownership,
        engine_retained_bytes,
        core_peak_bytes,
    };
    validate_memory_sample(memory);
    memory
}

fn validate_memory_sample(sample: MemorySample) {
    assert!(
        sample.engine_retained_bytes > 0,
        "engine retained denominator must be non-zero"
    );
    assert!(
        sample.core_peak_bytes >= sample.engine_retained_bytes,
        "core peak cannot be smaller than the retained Engine"
    );
    let core_peak_bytes = sample.core_peak_bytes;
    let end_to_end_peak_bytes = sample
        .ownership
        .source_record_bytes
        .checked_add(sample.ownership.source_checkpoint_bytes)
        .and_then(|source| source.checked_add(core_peak_bytes))
        .expect("end-to-end peak bytes fit");
    let core_ratio = checked_ratio(core_peak_bytes, sample.engine_retained_bytes);
    let end_to_end_ratio = checked_ratio(end_to_end_peak_bytes, sample.engine_retained_bytes);
    assert!(core_ratio.is_finite(), "core peak ratio must be finite");
    assert!(
        end_to_end_ratio.is_finite(),
        "end-to-end peak ratio must be finite"
    );
}

fn checked_ratio(numerator: usize, denominator: usize) -> f64 {
    assert!(denominator > 0, "ratio denominator must be non-zero");
    let ratio = numerator as f64 / denominator as f64;
    assert!(ratio.is_finite(), "ratio must be finite");
    ratio
}

fn freshness(boot: u64, journal: u64) -> Freshness {
    Freshness::new(
        BootGeneration::new(boot).expect("non-zero boot"),
        RegistryInstance::new(1).expect("non-zero registry"),
        DeviceGeneration::new(1).expect("non-zero device"),
        JournalGeneration::new(journal).expect("non-zero journal"),
    )
}

fn next_recovery_freshness(current: Freshness) -> Freshness {
    Freshness::new(
        BootGeneration::new(current.boot().get() + 1).expect("boot generation fits"),
        current.registry(),
        current.device(),
        JournalGeneration::new(current.journal().get() + 1).expect("journal generation fits"),
    )
}

fn limits(records: usize) -> CoreLimits {
    CoreLimits::new(
        records + 8,
        records + 8,
        records + 8,
        records + 8,
        4,
        1 << 20,
        1024,
    )
    .expect("valid profile limits")
}

struct BaseFixture {
    engine: Engine,
    source_journal: Vec<u8>,
    catalog: CatalogSet,
    limits: CoreLimits,
}

/// A sink which counts exact bytes but never retains them.  This is the
/// measured StreamingJournalBackend; its storage ownership is intentionally
/// zero for both record and checkpoint bytes.
#[derive(Debug, Default)]
struct CountingStreamingJournal {
    staged_bytes: usize,
    stage_calls: usize,
}

#[derive(Debug, Default)]
struct CountingCheckpointSink {
    bytes: usize,
}

impl CheckpointWrite for CountingCheckpointSink {
    type Error = Infallible;

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .expect("staged byte count fits");
        // Prevent a sufficiently aggressive optimizer from treating this as
        // an unused zero-work sink while retaining no input bytes.
        black_box(bytes.len());
        Ok(())
    }
}

impl StreamingJournalBackend for CountingStreamingJournal {
    type Error = Infallible;

    fn stage_checkpoint(&mut self, plan: &CheckpointRecordPlan) -> Result<(), Self::Error> {
        let mut sink = CountingCheckpointSink::default();
        let written = plan.write_to(&mut sink)?;
        assert_eq!(written, plan.record_len());
        assert_eq!(sink.bytes, plan.record_len());
        self.staged_bytes = sink.bytes;
        self.stage_calls = self.stage_calls.saturating_add(1);
        Ok(())
    }
}

/// In-memory trusted anchor used only to make the protocol fixture complete.
/// It has no filesystem, TPM, or other anchor I/O.  The measured publication
/// row can therefore report the assignment-only suffix without charging an
/// external anchor operation.
#[derive(Clone, Copy, Debug)]
struct InMemoryTrustedAnchor {
    committed: TrustedAnchorSnapshot,
    issued: Freshness,
    last_compare_nanos: u128,
    last_compare_allocations: AllocationSample,
}

impl TrustedAnchorBackend for InMemoryTrustedAnchor {
    type Error = Infallible;

    fn reserve_recovery_epoch(
        &mut self,
        binding: RecoveryBinding,
        observed_device: DeviceGeneration,
    ) -> Result<RecoveryLease, Self::Error> {
        assert_eq!(binding, self.committed.binding());
        assert!(observed_device.get() >= self.committed.committed_freshness().device().get());
        self.issued = next_recovery_freshness(self.issued);
        RecoveryLease::from_trusted_backend(self.committed, self.issued)
            .map_err(|_| unreachable!("fixture anchor coordinates are valid"))
    }

    fn compare_and_advance(
        &mut self,
        expected: TrustedAnchorSnapshot,
        replacement: TrustedAnchorSnapshot,
    ) -> Result<(), Self::Error> {
        assert_eq!(expected, self.committed);
        let before = allocations();
        let start = Instant::now();
        self.committed = replacement;
        self.last_compare_nanos = start.elapsed().as_nanos();
        self.last_compare_allocations = AllocationSample {
            calls: allocations().calls.saturating_sub(before.calls),
            bytes: allocations().bytes.saturating_sub(before.bytes),
            peak_live_bytes: allocations()
                .peak_live_bytes
                .saturating_sub(before.peak_live_bytes),
        };
        Ok(())
    }
}

type ProfilePersistence = CoordinatedPersistence<CountingStreamingJournal, InMemoryTrustedAnchor>;

struct StreamingFixture {
    engine: Engine,
    source_journal: Vec<u8>,
    catalog: CatalogSet,
    limits: CoreLimits,
    persistence: ProfilePersistence,
}

fn recovery_binding(engine: &Engine, catalog: &CatalogSet) -> RecoveryBinding {
    RecoveryBinding::new(
        RecoveryProfile::current(),
        engine.world(),
        catalog.digest(),
        engine.freshness().registry(),
    )
    .expect("valid recovery binding")
}

fn profile_persistence(engine: &Engine, catalog: &CatalogSet) -> ProfilePersistence {
    let binding = recovery_binding(engine, catalog);
    let committed = TrustedAnchorSnapshot::from_trusted_backend(
        binding,
        engine.freshness(),
        engine.revision(),
        engine.head(),
        engine.projection_digest(),
    )
    .expect("valid trusted fixture anchor");
    let next = next_recovery_freshness(engine.freshness());
    let lease = RecoveryLease::from_trusted_backend(committed, next)
        .expect("valid reserved recovery epoch");
    CoordinatedPersistence::from_recovery_lease(
        CountingStreamingJournal::default(),
        InMemoryTrustedAnchor {
            committed,
            issued: next,
            last_compare_nanos: 0,
            last_compare_allocations: AllocationSample::default(),
        },
        &lease,
    )
}

fn streaming_fixture(n: usize) -> StreamingFixture {
    let base = base_fixture(n);
    let persistence = profile_persistence(&base.engine, &base.catalog);
    StreamingFixture {
        engine: base.engine,
        source_journal: base.source_journal,
        catalog: base.catalog,
        limits: base.limits,
        persistence,
    }
}

fn transact(engine: &mut Engine, journal: &mut Vec<u8>, command: CommandRequest) {
    engine
        .transact(command, |record| {
            journal.extend_from_slice(record.bytes());
            Ok::<(), Infallible>(())
        })
        .expect("in-memory setup transition succeeds");
}

fn base_fixture(n: usize) -> BaseFixture {
    let world = WorldId::new(WORLD).expect("non-zero world");
    let catalog = standard_catalog();
    let verifier_bindings: Vec<VerifierBinding> = catalog
        .verifier_class_bindings()
        .into_iter()
        .enumerate()
        .map(|(index, class)| {
            VerifierBinding::new(
                class.verifier(),
                VerifierGeneration::new(1).expect("non-zero verifier generation"),
                class.receipt_schema(),
                Digest::new([0x40u8.wrapping_add(index as u8); 32]),
            )
            .expect("valid verifier binding")
        })
        .collect();
    let catalog_set = CatalogSet::new(std::slice::from_ref(&catalog)).expect("valid catalog set");
    let limits = limits(n);
    let mut engine = Engine::new(world, catalog_set.clone(), limits, freshness(1, 1));
    // This is an explicit source-owned setup journal.  It is built before all
    // phase counters are reset and is never an implicit backend staging copy.
    let mut source_journal = Vec::with_capacity(n.saturating_mul(1024));

    for index in 0..n {
        let ordinal = index as u64;
        let provider = ProviderCoordinate::new(
            world,
            ProviderId::new(PROVIDER_BASE + ordinal).expect("provider id fits"),
            ProviderGeneration::new(1).expect("provider generation fits"),
        );
        transact(
            &mut engine,
            &mut source_journal,
            CommandRequest::RegisterProviderGeneration {
                coordinate: provider,
                catalog_digest: catalog.digest(),
                verifier_bindings: verifier_bindings.clone(),
            },
        );
        let operation = OperationId::new(OPERATION_BASE + ordinal).expect("operation id fits");
        let effect = cser_core::EffectId::new(operation, 1).expect("effect id fits");
        let actor = ExecutorCoordinate::new(
            ExecutorId::new(ACTOR_BASE + ordinal).expect("executor id fits"),
            ExecutorGeneration::new(1).expect("executor generation fits"),
        );
        transact(
            &mut engine,
            &mut source_journal,
            CommandRequest::AdmitScopedCompositeEffect {
                effect,
                origin: actor,
                kind: AGENT_OPERATION_COMPOSITE,
                charge_account: cser_core::ChargeAccountId::new(OPERATION_BASE + ordinal)
                    .expect("charge account fits"),
                bindings: vec![
                    ComponentProviderBinding::new(AGENT_COMPONENT_REPLY, provider),
                    ComponentProviderBinding::new(AGENT_COMPONENT_DMA, provider),
                ],
            },
        );
    }
    assert_eq!(engine.revision(), (n * 2) as u64);
    BaseFixture {
        engine,
        source_journal,
        catalog: catalog_set,
        limits,
    }
}

struct RecoveryInput {
    /// Explicit source-owned canonical checkpoint record.
    bytes: Vec<u8>,
    catalog: CatalogSet,
    limits: CoreLimits,
    committed: TrustedAnchorSnapshot,
    next: Freshness,
}

impl RecoveryInput {
    fn anchor(&self) -> RecoveryAnchor {
        RecoveryAnchor::from_trusted_provider(
            self.committed.binding(),
            self.committed.committed_freshness(),
            self.next,
            self.committed.revision(),
            self.committed.head(),
            self.committed.projection(),
        )
        .expect("valid recovery anchor")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PositionedSourceError {
    SnapshotChanged,
    OutOfRange,
}

/// Borrowed in-memory positioned source for the recovery profile.  The
/// checkpoint bytes remain owned by `RecoveryInput`; this adapter only counts
/// fixed-scratch reads and copies each requested range into Core's scratch.
struct PositionedMemorySource<'a> {
    bytes: &'a [u8],
    reads: usize,
    bytes_read: usize,
}

impl<'a> PositionedMemorySource<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            reads: 0,
            bytes_read: 0,
        }
    }
}

impl JournalRecoverySource for PositionedMemorySource<'_> {
    type Error = PositionedSourceError;
    type Snapshot = usize;

    fn begin_snapshot(&mut self) -> Result<RecoverySourceSnapshot<Self::Snapshot>, Self::Error> {
        Ok(RecoverySourceSnapshot::new(
            self.bytes.len(),
            self.bytes.len() as u64,
        ))
    }

    fn read_exact_at(
        &mut self,
        snapshot: Self::Snapshot,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        if snapshot != self.bytes.len() {
            return Err(PositionedSourceError::SnapshotChanged);
        }
        let start = usize::try_from(offset).map_err(|_| PositionedSourceError::OutOfRange)?;
        let end = start
            .checked_add(output.len())
            .ok_or(PositionedSourceError::OutOfRange)?;
        let source = self
            .bytes
            .get(start..end)
            .ok_or(PositionedSourceError::OutOfRange)?;
        output.copy_from_slice(source);
        self.reads = self.reads.saturating_add(1);
        self.bytes_read = self.bytes_read.saturating_add(output.len());
        Ok(())
    }

    fn validate_snapshot(&mut self, snapshot: Self::Snapshot) -> Result<(), Self::Error> {
        (snapshot == self.bytes.len())
            .then_some(())
            .ok_or(PositionedSourceError::SnapshotChanged)
    }
}

struct ProfileArtifacts {
    source_checkpoint_bytes: usize,
    first: RecoveryInput,
}

/// Captures one canonical record solely as a source fixture for recovery.
/// This allocation is outside every timed phase and is separately reported as
/// `source_checkpoint_bytes`, never as `checkpoint_owned_copy_bytes`.
fn source_checkpoint_bytes(engine: &Engine) -> Vec<u8> {
    let snapshot = engine
        .checkpoint_snapshot()
        .expect("checkpoint snapshot creates");
    let plan = snapshot.prepare_plan().expect("checkpoint plan creates");
    let mut bytes = Vec::with_capacity(plan.record_len());
    let written = plan
        .write_to(&mut bytes)
        .map_err(|never| match never {})
        .expect("source checkpoint stream succeeds");
    assert_eq!(written, plan.record_len());
    assert_eq!(bytes.len(), plan.record_len());
    bytes
}

fn checkpoint_artifacts(n: usize) -> ProfileArtifacts {
    let mut fixture = streaming_fixture(n);
    let checkpoint_bytes = source_checkpoint_bytes(&fixture.engine);
    let snapshot = fixture
        .engine
        .checkpoint_snapshot()
        .expect("checkpoint snapshot creates");
    let plan = snapshot.prepare_plan().expect("checkpoint plan creates");
    assert_eq!(plan.record_len(), checkpoint_bytes.len());
    drop(plan);
    // Exercise the public one-call canonical wrapper in the artifact setup.
    // Timed rows below invoke the same calls individually so each authority
    // boundary remains visible in the evidence.
    fixture
        .engine
        .compact_checkpoint_streaming(&mut fixture.persistence)
        .expect("checkpoint anchor and publication succeed");
    let committed = fixture.persistence.committed();
    let first = RecoveryInput {
        bytes: checkpoint_bytes,
        catalog: fixture.catalog.clone(),
        limits: fixture.limits,
        committed,
        next: next_recovery_freshness(committed.committed_freshness()),
    };
    ProfileArtifacts {
        source_checkpoint_bytes: first.bytes.len(),
        first,
    }
}

fn plan_to_prepared(
    engine: &mut Engine,
    plan: CheckpointRecordPlan,
) -> cser_core::PreparedCheckpoint {
    engine
        .checkpoint_prepare(plan)
        .expect("checkpoint prepare succeeds")
}

fn ownership(fixture: &StreamingFixture, checkpoint_bytes: usize) -> OwnershipSample {
    OwnershipSample {
        source_record_bytes: fixture.source_journal.capacity(),
        source_checkpoint_bytes: checkpoint_bytes,
        // CountingStreamingJournal and CountingCheckpointSink retain no bytes.
        record_owned_copy_bytes: 0,
        checkpoint_owned_copy_bytes: 0,
        staged_bytes: 0,
    }
}

fn collect_samples(mut sample: impl FnMut() -> PhaseSample) -> Vec<PhaseSample> {
    for _ in 0..WARMUPS {
        black_box(sample());
    }
    (0..SAMPLES).map(|_| sample()).collect()
}

fn sample_snapshot_capture(n: usize, checkpoint_bytes: usize) -> PhaseSample {
    let fixture = streaming_fixture(n);
    let ownership = ownership(&fixture, checkpoint_bytes);
    reset_allocations();
    let base_live_bytes = live_bytes();
    let start = Instant::now();
    let snapshot = fixture
        .engine
        .checkpoint_snapshot()
        .expect("checkpoint snapshot succeeds");
    let nanos = start.elapsed().as_nanos();
    black_box(&snapshot);
    let allocations = allocations();
    let peak_live_bytes = peak_live_bytes();
    drop(snapshot);
    let memory = finish_existing_engine(fixture, ownership, base_live_bytes, peak_live_bytes);
    PhaseSample {
        nanos,
        allocations,
        memory,
        ..PhaseSample::default()
    }
}

fn sample_plan_count_hash(n: usize, checkpoint_bytes: usize) -> PhaseSample {
    let mut fixture = streaming_fixture(n);
    let snapshot = fixture
        .engine
        .checkpoint_snapshot()
        .expect("checkpoint snapshot succeeds");
    reset_allocations();
    let base_live_bytes = live_bytes();
    let start = Instant::now();
    let plan = snapshot
        .prepare_plan()
        .expect("checkpoint plan/count/hash succeeds");
    // Include the semantic prepare that seals the assignment-only delta in
    // this phase.  Stage/encode starts only after this value is ready.
    let prepared = fixture
        .engine
        .checkpoint_prepare(plan)
        .expect("checkpoint semantic prepare succeeds");
    let nanos = start.elapsed().as_nanos();
    black_box(Engine::checkpoint_plan(&prepared).record_len());
    let allocations = allocations();
    let peak_live_bytes = peak_live_bytes();
    drop(prepared);
    let ownership = ownership(&fixture, checkpoint_bytes);
    let memory = finish_existing_engine(fixture, ownership, base_live_bytes, peak_live_bytes);
    PhaseSample {
        nanos,
        allocations,
        memory,
        ..PhaseSample::default()
    }
}

fn prepared_fixture(n: usize) -> (StreamingFixture, cser_core::PreparedCheckpoint) {
    let mut fixture = streaming_fixture(n);
    let snapshot = fixture
        .engine
        .checkpoint_snapshot()
        .expect("checkpoint snapshot succeeds");
    let plan = snapshot
        .prepare_plan()
        .expect("checkpoint plan/count/hash succeeds");
    let prepared = plan_to_prepared(&mut fixture.engine, plan);
    (fixture, prepared)
}

fn sample_stage_encode(n: usize, checkpoint_bytes: usize) -> PhaseSample {
    let (mut fixture, prepared) = prepared_fixture(n);
    let mut ownership = ownership(&fixture, checkpoint_bytes);
    reset_allocations();
    let base_live_bytes = live_bytes();
    let start = Instant::now();
    let durable = prepared
        .persist_checkpoint(&mut fixture.persistence)
        .expect("checkpoint stage/encode succeeds");
    let nanos = start.elapsed().as_nanos();
    black_box(fixture.persistence.journal().staged_bytes);
    ownership.staged_bytes = fixture.persistence.journal().staged_bytes;
    let allocations = allocations();
    let peak_live_bytes = peak_live_bytes();
    drop(durable);
    let memory = finish_existing_engine(fixture, ownership, base_live_bytes, peak_live_bytes);
    PhaseSample {
        nanos,
        allocations,
        memory,
        ..PhaseSample::default()
    }
}

/// Measures the in-memory anchor call plus the assignment-only publication.
///
/// This is deliberately reported as an upper bound for the post-anchor
/// suffix, not as a post-anchor-only timer: the public authority API does not
/// expose an unsafe split between anchor advancement and Engine publication.
/// `anchor_nanos` keeps the fixture's in-memory compare cost visible.
fn sample_anchor_and_publication(n: usize, checkpoint_bytes: usize) -> PhaseSample {
    let (mut fixture, prepared) = prepared_fixture(n);
    let durable = prepared
        .persist_checkpoint(&mut fixture.persistence)
        .expect("checkpoint stage/encode succeeds");
    reset_allocations();
    let base_live_bytes = live_bytes();
    let start = Instant::now();
    let receipt = fixture
        .engine
        .checkpoint_publish(durable, &mut fixture.persistence)
        .expect("checkpoint anchor/publication succeeds");
    let nanos = start.elapsed().as_nanos();
    black_box(receipt.revision());
    let allocations = allocations();
    let peak_live_bytes = peak_live_bytes();
    let anchor = *fixture.persistence.anchor();
    let ownership = ownership_for_no_stage(&fixture, checkpoint_bytes);
    let memory = finish_existing_engine(fixture, ownership, base_live_bytes, peak_live_bytes);
    PhaseSample {
        nanos,
        allocations,
        memory,
        anchor_nanos: anchor.last_compare_nanos,
        anchor_allocations: anchor.last_compare_allocations,
        ..PhaseSample::default()
    }
}

fn ownership_for_no_stage(fixture: &StreamingFixture, checkpoint_bytes: usize) -> OwnershipSample {
    ownership(fixture, checkpoint_bytes)
}

/// Measures the public positioned recovery path with a fixed 4 KiB scratch
/// buffer.  The source read counters are captured before the source is
/// dropped, and are not inferred from the checkpoint's contiguous length.
fn sample_first_recovery(input: &RecoveryInput) -> PhaseSample {
    let ownership = OwnershipSample {
        source_record_bytes: 0,
        source_checkpoint_bytes: input.bytes.capacity(),
        record_owned_copy_bytes: 0,
        checkpoint_owned_copy_bytes: 0,
        staged_bytes: 0,
    };
    let anchor = input.anchor();
    reset_allocations();
    let base_live_bytes = live_bytes();
    // The catalog clone becomes owned by the recovered Engine.  Create it
    // after establishing the source-fixture baseline so both the retained
    // denominator and the peak numerator account for the same ownership.
    let catalog = input.catalog.clone();
    let mut source = PositionedMemorySource::new(&input.bytes);
    let mut scratch = [0u8; 4096];
    let start = Instant::now();
    let report =
        Engine::recover_from_source(catalog, input.limits, anchor, &mut source, &mut scratch)
            .expect("first positioned checkpoint recovery succeeds");
    let nanos = start.elapsed().as_nanos();
    black_box(report.acknowledged_revision());
    let engine = report.into_engine();
    let allocations = allocations();
    let peak_live_bytes = peak_live_bytes();
    let recovery_reads = source.reads;
    let recovery_read_bytes = source.bytes_read;
    let memory = finish_recovery_engine(
        input,
        input.catalog.clone(),
        engine,
        ownership,
        base_live_bytes,
        peak_live_bytes,
    );
    PhaseSample {
        nanos,
        allocations,
        memory,
        recovery_reads,
        recovery_read_bytes,
        ..PhaseSample::default()
    }
}

fn percentile(samples: &[PhaseSample], percent: usize) -> u128 {
    assert!(!samples.is_empty(), "percentile requires samples");
    let mut values: Vec<u128> = samples.iter().map(|sample| sample.nanos).collect();
    values.sort_unstable();
    let rank = values.len().saturating_mul(percent).saturating_add(99) / 100;
    values[rank.saturating_sub(1).min(values.len() - 1)]
}

fn median_by<T: Ord + Copy>(samples: &[PhaseSample], select: impl Fn(PhaseSample) -> T) -> T {
    let mut values: Vec<T> = samples.iter().copied().map(select).collect();
    values.sort_unstable();
    values[values.len() / 2]
}

fn print_row(workload: &str, n: usize, samples: &[PhaseSample], recovery_mode: &str) {
    let median_ns = percentile(samples, 50);
    let p95_ns = percentile(samples, 95);
    let p99_ns = percentile(samples, 99);
    let median_allocations = median_by(samples, |sample| sample.allocations.calls);
    let median_alloc_bytes = median_by(samples, |sample| sample.allocations.bytes);
    let median_peak_live_bytes = median_by(samples, |sample| sample.allocations.peak_live_bytes);
    let median_source_record_bytes = median_by(samples, |sample| {
        sample.memory.ownership.source_record_bytes
    });
    let median_source_checkpoint_bytes = median_by(samples, |sample| {
        sample.memory.ownership.source_checkpoint_bytes
    });
    let median_staged_bytes = median_by(samples, |sample| sample.memory.ownership.staged_bytes);
    let median_engine_retained_bytes =
        median_by(samples, |sample| sample.memory.engine_retained_bytes);
    let median_core_peak_bytes = median_by(samples, |sample| sample.memory.core_peak_bytes);
    let median_transient_peak_bytes = median_core_peak_bytes
        .checked_sub(median_engine_retained_bytes)
        .expect("median core peak includes retained Engine");
    let median_record_owned_copy_bytes = median_by(samples, |sample| {
        sample.memory.ownership.record_owned_copy_bytes
    });
    let median_checkpoint_owned_copy_bytes = median_by(samples, |sample| {
        sample.memory.ownership.checkpoint_owned_copy_bytes
    });
    let median_anchor_nanos = median_by(samples, |sample| sample.anchor_nanos);
    let median_anchor_allocations = median_by(samples, |sample| sample.anchor_allocations.calls);
    let median_anchor_alloc_bytes = median_by(samples, |sample| sample.anchor_allocations.bytes);
    let median_recovery_reads = median_by(samples, |sample| sample.recovery_reads);
    let median_recovery_read_bytes = median_by(samples, |sample| sample.recovery_read_bytes);
    let median_end_to_end_peak_bytes = median_source_record_bytes
        .checked_add(median_source_checkpoint_bytes)
        .and_then(|source| source.checked_add(median_core_peak_bytes))
        .expect("median end-to-end peak bytes fit");
    let core_peak_ratio = checked_ratio(median_core_peak_bytes, median_engine_retained_bytes);
    let end_to_end_peak_ratio =
        checked_ratio(median_end_to_end_peak_bytes, median_engine_retained_bytes);
    println!(
        "{workload},{n},{WARMUPS},{SAMPLES},{median_ns},{p95_ns},{p99_ns},{median_allocations},{median_alloc_bytes},{median_peak_live_bytes},{median_source_record_bytes},{median_source_checkpoint_bytes},{median_staged_bytes},{median_engine_retained_bytes},{median_transient_peak_bytes},{core_peak_ratio:.6},{end_to_end_peak_ratio:.6},{median_record_owned_copy_bytes},{median_checkpoint_owned_copy_bytes},{median_anchor_nanos},{median_anchor_allocations},{median_anchor_alloc_bytes},{median_recovery_reads},{median_recovery_read_bytes},{recovery_mode}"
    );
}

fn parse_sizes() -> Vec<usize> {
    env::var("CSER_PROFILE_SIZES")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(|value| {
                    let n = value
                        .trim()
                        .parse::<usize>()
                        .unwrap_or_else(|_| panic!("invalid profile N: {value:?}"));
                    assert!(n > 0, "profile N must be non-zero");
                    n
                })
                .collect()
        })
        .unwrap_or_else(|| DEFAULT_SIZES.to_vec())
}

fn main() {
    if cfg!(feature = "test-support") || cfg!(feature = "full-invariant-oracle") {
        eprintln!(
            "cser_checkpoint_profile requires the production transition gate; rerun with --no-default-features"
        );
        std::process::exit(2);
    }
    println!(
        "workload,N,warmups,samples,median_ns,p95_ns,p99_ns,median_allocations,median_alloc_bytes,median_peak_live_bytes,source_record_bytes,source_checkpoint_bytes,staged_bytes,engine_retained_bytes,transient_peak_bytes,core_peak_ratio,end_to_end_peak_ratio,record_owned_copy_bytes,checkpoint_owned_copy_bytes,anchor_in_memory_ns,anchor_allocations,anchor_alloc_bytes,recovery_read_at_calls,recovery_read_at_bytes,recovery_mode"
    );
    eprintln!(
        "streaming phases: snapshot capture; plan/count/hash; stage/encode; anchor + post-anchor publication"
    );
    eprintln!("recovery API status: positioned JournalRecoverySource with fixed 4096-byte scratch");
    for n in parse_sizes() {
        let artifacts = checkpoint_artifacts(n);
        let snapshot =
            collect_samples(|| sample_snapshot_capture(n, artifacts.source_checkpoint_bytes));
        let plan = collect_samples(|| sample_plan_count_hash(n, artifacts.source_checkpoint_bytes));
        let stage = collect_samples(|| sample_stage_encode(n, artifacts.source_checkpoint_bytes));
        let anchor =
            collect_samples(|| sample_anchor_and_publication(n, artifacts.source_checkpoint_bytes));
        let first = collect_samples(|| sample_first_recovery(&artifacts.first));
        print_row("snapshot_capture", n, &snapshot, "not_applicable");
        print_row("plan_count_hash", n, &plan, "not_applicable");
        print_row("stage_encode", n, &stage, "not_applicable");
        print_row(
            "anchor_and_post_anchor_publication",
            n,
            &anchor,
            "in_memory_anchor_no_io",
        );
        print_row("first_checkpoint_recovery", n, &first, "positioned_read_at");
    }
}

#[cfg(test)]
mod tests {
    use super::{MemorySample, OwnershipSample, checked_ratio, validate_memory_sample};

    #[test]
    fn memory_ratios_are_finite_for_a_valid_retained_denominator() {
        let sample = MemorySample {
            ownership: OwnershipSample {
                source_record_bytes: 16,
                source_checkpoint_bytes: 32,
                record_owned_copy_bytes: 0,
                checkpoint_owned_copy_bytes: 0,
                staged_bytes: 48,
            },
            engine_retained_bytes: 100,
            core_peak_bytes: 125,
        };
        validate_memory_sample(sample);
        assert_eq!(checked_ratio(125, 100), 1.25);
        assert_eq!(checked_ratio(173, 100), 1.73);
    }

    #[test]
    #[should_panic(expected = "ratio denominator must be non-zero")]
    fn memory_ratio_rejects_zero_denominator() {
        let _ = checked_ratio(1, 0);
    }
}
