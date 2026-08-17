//! Small release profile for checkpoint preparation, durability, and recovery.
//!
//! This example uses only the public production API and an in-memory
//! `TransitionDurability`.  It is deliberately a measurement helper rather
//! than a benchmark gate: rows report medians for a fixed warmup/sample count
//! and do not establish a general performance claim.
//!
//! Run with:
//!
//! ```text
//! cargo run --release --no-default-features -p cser-core \
//!   --example cser_checkpoint_profile
//! ```
//!
//! The default sizes are 1, 64, and 512.  Set `CSER_PROFILE_SIZES=4096` (or a
//! comma-separated list) to include a larger fixture when it is affordable.

use core::convert::Infallible;
use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration,
    CatalogSet, CommandRequest, ComponentProviderBinding, CoreLimits, DeviceGeneration, Digest,
    Engine, ExecutorCoordinate, ExecutorGeneration, ExecutorId, Freshness, JournalCheckpoint,
    JournalGeneration, OperationId, ProviderCoordinate, ProviderGeneration, ProviderId,
    RecoveryAnchor, RecoveryBinding, RecoveryProfile, RegistryInstance, TransitionDurability,
    VerifierBinding, VerifierGeneration, WorldId, standard_catalog,
};

const WORLD: u64 = 1;
const PROVIDER_BASE: u64 = 10_000;
const OPERATION_BASE: u64 = 20_000;
const ACTOR_BASE: u64 = 30_000;

const DEFAULT_SIZES: [usize; 3] = [1, 64, 512];
const SUFFIX_TRANSITIONS: usize = 1;
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
    let live = LIVE_BYTES.load(Ordering::Relaxed);
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

fn subtract_allocations(total: AllocationSample, nested: AllocationSample) -> AllocationSample {
    AllocationSample {
        calls: total.calls.saturating_sub(nested.calls),
        bytes: total.bytes.saturating_sub(nested.bytes),
        // Nested phase peaks are reported as the additional high-water mark
        // observed after that phase began. This is exact for the preallocated
        // in-memory durability callback used by this profile.
        peak_live_bytes: total.peak_live_bytes.saturating_sub(nested.peak_live_bytes),
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PhaseSample {
    nanos: u128,
    allocations: AllocationSample,
}

fn median_by<T: Ord + Copy>(samples: &[PhaseSample], select: impl Fn(PhaseSample) -> T) -> T {
    let mut values: Vec<T> = samples.iter().copied().map(select).collect();
    values.sort_unstable();
    values[values.len() / 2]
}

fn freshness(boot: u64, journal: u64) -> Freshness {
    Freshness::new(
        BootGeneration::new(boot).expect("non-zero boot"),
        RegistryInstance::new(1).expect("non-zero registry"),
        DeviceGeneration::new(1).expect("non-zero device"),
        JournalGeneration::new(journal).expect("non-zero journal"),
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

#[derive(Clone, Copy)]
struct ProviderTarget {
    coordinate: ProviderCoordinate,
}

struct Fixture {
    engine: Engine,
    journal: Vec<u8>,
    catalog: CatalogSet,
    limits: CoreLimits,
    suffix_targets: [ProviderTarget; SUFFIX_TRANSITIONS],
}

fn transact(engine: &mut Engine, journal: &mut Vec<u8>, command: CommandRequest) {
    engine
        .transact(command, |record| {
            journal.extend_from_slice(record.bytes());
            Ok::<(), Infallible>(())
        })
        .expect("in-memory production transition succeeds");
}

fn fixture(n: usize) -> Fixture {
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
    let records = n;
    let catalog_set = CatalogSet::new(std::slice::from_ref(&catalog)).expect("valid catalog set");
    let limits = limits(records);
    let mut engine = Engine::new(world, catalog_set.clone(), limits, freshness(1, 1));
    let mut journal = Vec::with_capacity(records.saturating_mul(1024));
    let suffix_targets = [ProviderTarget {
        coordinate: ProviderCoordinate::new(
            world,
            ProviderId::new(PROVIDER_BASE).expect("provider id fits"),
            ProviderGeneration::new(1).expect("provider generation fits"),
        ),
    }];

    for index in 0..records {
        let ordinal = index as u64;
        let provider = ProviderCoordinate::new(
            world,
            ProviderId::new(PROVIDER_BASE + ordinal).expect("provider id fits"),
            ProviderGeneration::new(1).expect("provider generation fits"),
        );
        transact(
            &mut engine,
            &mut journal,
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
            &mut journal,
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
    assert_eq!(engine.revision(), (records * 2) as u64);
    Fixture {
        engine,
        journal,
        catalog: catalog_set,
        limits,
        suffix_targets,
    }
}

struct MemoryPersistence {
    bytes: Vec<u8>,
    replace: bool,
    durable_nanos: u128,
    durable_allocations: AllocationSample,
}

impl MemoryPersistence {
    fn with_capacity(capacity: usize, replace: bool) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            replace,
            durable_nanos: 0,
            durable_allocations: AllocationSample::default(),
        }
    }

    fn append_mode(&mut self) {
        self.replace = false;
    }
}

impl TransitionDurability for MemoryPersistence {
    type Error = Infallible;

    fn persist_transition(
        &mut self,
        record: &cser_core::JournalRecord,
        _resulting_freshness: Freshness,
        _resulting_projection: Digest,
    ) -> Result<(), Self::Error> {
        let before = allocations();
        let start = Instant::now();
        if self.replace {
            self.bytes.clear();
        }
        self.bytes.extend_from_slice(record.bytes());
        self.replace = false;
        self.durable_nanos = start.elapsed().as_nanos();
        self.durable_allocations = subtract_allocations(allocations(), before);
        Ok(())
    }
}

struct RecoveryInput {
    bytes: Vec<u8>,
    catalog: CatalogSet,
    limits: CoreLimits,
    world: WorldId,
    committed: Freshness,
    next: Freshness,
    revision: u64,
    head: Digest,
    projection: Digest,
    checkpoint_bytes: usize,
}

struct ProfileArtifacts {
    reserve: usize,
    source_journal_bytes: usize,
    exact_checkpoint: JournalCheckpoint,
    first: RecoveryInput,
    suffix: RecoveryInput,
}

impl RecoveryInput {
    fn anchor(&self) -> RecoveryAnchor {
        let binding = RecoveryBinding::new(
            RecoveryProfile::current(),
            self.world,
            self.catalog.digest(),
            self.committed.registry(),
        )
        .expect("valid recovery binding");
        RecoveryAnchor::from_trusted_provider(
            binding,
            self.committed,
            self.next,
            self.revision,
            self.head,
            self.projection,
        )
        .expect("valid recovery anchor")
    }
}

fn checkpoint_artifacts(n: usize) -> ProfileArtifacts {
    let mut fixture = fixture(n);
    let source_journal_bytes = fixture.journal.len();
    let exact_checkpoint = fixture
        .engine
        .journal_checkpoint(&fixture.journal)
        .expect("exact replay checkpoint creates");
    let reserve = fixture
        .journal
        .len()
        .saturating_mul(4)
        .saturating_add(1 << 20);
    let mut persistence = MemoryPersistence::with_capacity(reserve, true);
    fixture
        .engine
        .compact_checkpoint_durable(&mut persistence)
        .expect("checkpoint persists in memory");
    let checkpoint_bytes = persistence.bytes.len();
    let checkpoint_journal = persistence.bytes.clone();
    let checkpoint_engine = &fixture.engine;
    let first = RecoveryInput {
        bytes: checkpoint_journal,
        catalog: fixture.catalog.clone(),
        limits: fixture.limits,
        world: WorldId::new(WORLD).expect("world fits"),
        committed: checkpoint_engine.freshness(),
        next: freshness(
            checkpoint_engine.freshness().boot().get() + 1,
            checkpoint_engine.freshness().journal().get() + 1,
        ),
        revision: checkpoint_engine.revision(),
        head: checkpoint_engine.head(),
        projection: checkpoint_engine.projection_digest(),
        checkpoint_bytes,
    };

    persistence.append_mode();
    for target in fixture.suffix_targets {
        fixture
            .engine
            .transact_durable(
                CommandRequest::FenceProviderEffects {
                    coordinate: target.coordinate,
                    expected_epoch: 1,
                },
                &mut persistence,
            )
            .expect("suffix transition persists in memory");
    }
    let suffix = RecoveryInput {
        bytes: persistence.bytes,
        catalog: fixture.catalog,
        limits: fixture.limits,
        world: WorldId::new(WORLD).expect("world fits"),
        committed: fixture.engine.freshness(),
        next: freshness(
            fixture.engine.freshness().boot().get() + 1,
            fixture.engine.freshness().journal().get() + 1,
        ),
        revision: fixture.engine.revision(),
        head: fixture.engine.head(),
        projection: fixture.engine.projection_digest(),
        checkpoint_bytes,
    };
    ProfileArtifacts {
        reserve,
        source_journal_bytes,
        exact_checkpoint,
        first,
        suffix,
    }
}

fn sample_checkpoint_create(n: usize) -> PhaseSample {
    let fixture = fixture(n);
    reset_allocations();
    let start = Instant::now();
    let checkpoint = fixture
        .engine
        .journal_checkpoint(&fixture.journal)
        .expect("checkpoint creates");
    let nanos = start.elapsed().as_nanos();
    black_box(checkpoint.anchor());
    PhaseSample {
        nanos,
        allocations: allocations(),
    }
}

fn sample_checkpoint_compact(n: usize, reserve: usize, prepare: bool) -> PhaseSample {
    let mut fixture = fixture(n);
    let mut persistence = MemoryPersistence::with_capacity(reserve, true);
    reset_allocations();
    let start = Instant::now();
    fixture
        .engine
        .compact_checkpoint_durable(&mut persistence)
        .expect("checkpoint persists in memory");
    let total_nanos = start.elapsed().as_nanos();
    let total_allocations = allocations();
    black_box(persistence.bytes.len());
    if prepare {
        PhaseSample {
            nanos: total_nanos.saturating_sub(persistence.durable_nanos),
            allocations: subtract_allocations(total_allocations, persistence.durable_allocations),
        }
    } else {
        PhaseSample {
            nanos: persistence.durable_nanos,
            allocations: persistence.durable_allocations,
        }
    }
}

fn sample_recovery(input: &RecoveryInput) -> PhaseSample {
    let catalog = input.catalog.clone();
    let anchor = input.anchor();
    reset_allocations();
    let start = Instant::now();
    let report = Engine::recover(catalog, input.limits, anchor, &input.bytes)
        .expect("checkpoint journal recovers");
    let nanos = start.elapsed().as_nanos();
    black_box(report.acknowledged_revision());
    PhaseSample {
        nanos,
        allocations: allocations(),
    }
}

fn sample_journal_checkpoint_recovery(
    checkpoint: &JournalCheckpoint,
    catalog: &CatalogSet,
    limits: CoreLimits,
) -> PhaseSample {
    let tip = checkpoint.anchor();
    let next = freshness(
        tip.freshness().boot().get() + 1,
        tip.freshness().journal().get() + 1,
    );
    let anchor = RecoveryAnchor::from_trusted_provider(
        tip.binding(),
        tip.freshness(),
        next,
        tip.revision(),
        tip.head(),
        tip.projection(),
    )
    .expect("checkpoint recovery anchor is monotonic");
    reset_allocations();
    let start = Instant::now();
    let report = checkpoint
        .recover(catalog.clone(), limits, anchor)
        .expect("journal checkpoint recovers");
    let nanos = start.elapsed().as_nanos();
    black_box(report.acknowledged_revision());
    PhaseSample {
        nanos,
        allocations: allocations(),
    }
}

fn collect_samples(mut sample: impl FnMut() -> PhaseSample) -> Vec<PhaseSample> {
    for _ in 0..WARMUPS {
        black_box(sample());
    }
    (0..SAMPLES).map(|_| sample()).collect()
}

fn print_row(
    workload: &str,
    n: usize,
    samples: &[PhaseSample],
    journal_bytes: usize,
    checkpoint_bytes: usize,
) {
    let median_nanos = median_by(samples, |sample| sample.nanos);
    let median_allocations = median_by(samples, |sample| sample.allocations.calls);
    let median_alloc_bytes = median_by(samples, |sample| sample.allocations.bytes);
    let median_peak_live_bytes = median_by(samples, |sample| sample.allocations.peak_live_bytes);
    println!(
        "{workload},{n},{WARMUPS},{SAMPLES},{median_nanos},{median_allocations},{median_alloc_bytes},{median_peak_live_bytes},{journal_bytes},{checkpoint_bytes}"
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
            "cser_checkpoint_profile requires the production transition gate; \
             rerun with --no-default-features"
        );
        std::process::exit(2);
    }
    println!(
        "workload,N,warmups,samples,median_ns,median_allocations,median_alloc_bytes,median_peak_live_bytes,journal_bytes,checkpoint_bytes"
    );
    for n in parse_sizes() {
        let artifacts = checkpoint_artifacts(n);
        let create = collect_samples(|| sample_checkpoint_create(n));
        let prepare = collect_samples(|| sample_checkpoint_compact(n, artifacts.reserve, true));
        let durable = collect_samples(|| sample_checkpoint_compact(n, artifacts.reserve, false));
        let journal_checkpoint = collect_samples(|| {
            sample_journal_checkpoint_recovery(
                &artifacts.exact_checkpoint,
                &artifacts.first.catalog,
                artifacts.first.limits,
            )
        });
        let first = collect_samples(|| sample_recovery(&artifacts.first));
        let suffix = collect_samples(|| sample_recovery(&artifacts.suffix));
        print_row(
            "checkpoint_create",
            n,
            &create,
            artifacts.source_journal_bytes,
            artifacts.exact_checkpoint.encode().len(),
        );
        print_row(
            "checkpoint_prepare",
            n,
            &prepare,
            artifacts.source_journal_bytes,
            artifacts.first.checkpoint_bytes,
        );
        print_row(
            "checkpoint_durable",
            n,
            &durable,
            artifacts.source_journal_bytes,
            artifacts.first.checkpoint_bytes,
        );
        print_row(
            "journal_checkpoint_recovery",
            n,
            &journal_checkpoint,
            artifacts.source_journal_bytes,
            artifacts.exact_checkpoint.encode().len(),
        );
        print_row(
            "first_checkpoint_recovery",
            n,
            &first,
            artifacts.first.bytes.len(),
            artifacts.first.checkpoint_bytes,
        );
        print_row(
            "checkpoint_suffix_replay",
            n,
            &suffix,
            artifacts.suffix.bytes.len(),
            artifacts.suffix.checkpoint_bytes,
        );
    }
}
