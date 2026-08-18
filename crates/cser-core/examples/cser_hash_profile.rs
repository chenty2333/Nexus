//! Small host SHA-256 profile paired with checkpoint/recovery measurements.
//!
//! This is a deliberately narrow microbenchmark, not a performance gate. Run
//! the two comparable builds with the same command and `--no-default-features`:
//!
//! ```text
//! cargo run --release -p cser-core --no-default-features --features std \\
//!     --example cser_hash_profile
//! cargo run --release -p cser-core --no-default-features \\
//!     --features std,sha2-software-baseline --example cser_hash_profile
//! ```
//!
//! Hash rows report input throughput. Checkpoint rows include the encoded
//! envelope size and the exact byte count supplied to recovery, so a hash
//! backend comparison remains tied to the checkpoint/recovery workload rather
//! than becoming an unrelated CPU-only number. CPU/backend observations are
//! diagnostic labels only; canonical bytes and successful recovery remain the
//! authority.

use std::env;
use std::hint::black_box;
use std::time::{Duration, Instant};

use cser_core::{
    BootGeneration, CatalogSet, CoreLimits, DeviceGeneration, Digest, Engine, Freshness,
    JournalCheckpoint, JournalGeneration, RecoveryAnchor, RegistryInstance, WorldId,
    standard_catalog,
};
use sha2::{Digest as _, Sha256};

const DEFAULT_SIZES: [usize; 3] = [64, 4 * 1024, 1024 * 1024];
const WARMUPS: usize = 2;
const SAMPLES: usize = 7;
const TARGET_HASH_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
struct CheckpointFixture {
    catalog: CatalogSet,
    limits: CoreLimits,
    checkpoint: JournalCheckpoint,
    encoded: Vec<u8>,
}

fn freshness(boot: u64, journal: u64) -> Freshness {
    Freshness::new(
        BootGeneration::new(boot).expect("non-zero boot"),
        RegistryInstance::new(1).expect("non-zero registry"),
        DeviceGeneration::new(1).expect("non-zero device"),
        JournalGeneration::new(journal).expect("non-zero journal"),
    )
}

fn checkpoint_fixture() -> CheckpointFixture {
    let world = WorldId::new(1).expect("non-zero world");
    let catalog = standard_catalog();
    let catalog_set = CatalogSet::new(std::slice::from_ref(&catalog)).expect("valid catalog");
    let limits = CoreLimits::new(4, 4, 4, 4, 4, 64, 4).expect("valid limits");
    let engine = Engine::new(world, catalog_set.clone(), limits, freshness(1, 1));
    // Genesis is intentionally enough to exercise the canonical checkpoint
    // envelope and its full recovery path without constructing a second
    // benchmark fixture or changing semantic state.
    let checkpoint = engine
        .journal_checkpoint(&[])
        .expect("genesis checkpoint creates");
    let encoded = checkpoint.encode();
    CheckpointFixture {
        catalog: catalog_set,
        limits,
        checkpoint,
        encoded,
    }
}

fn payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(7))
        .collect()
}

fn hex_digest(digest: Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest.bytes() {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

fn hash_rounds(input: &[u8], rounds: usize) -> Duration {
    let started = Instant::now();
    for _ in 0..rounds {
        let digest = Sha256::digest(black_box(input));
        black_box(digest);
    }
    started.elapsed()
}

fn checkpoint_encode_sample(fixture: &CheckpointFixture) -> Duration {
    let started = Instant::now();
    black_box(fixture.checkpoint.encode());
    started.elapsed()
}

fn checkpoint_recovery_sample(fixture: &CheckpointFixture) -> Duration {
    let started = Instant::now();
    let checkpoint = JournalCheckpoint::decode(black_box(&fixture.encoded))
        .expect("profile checkpoint remains structurally valid");
    let anchor_data = checkpoint.anchor();
    let next_freshness = freshness(
        anchor_data.freshness().boot().get() + 1,
        anchor_data.freshness().journal().get() + 1,
    );
    let anchor = RecoveryAnchor::from_trusted_provider(
        anchor_data.binding(),
        anchor_data.freshness(),
        next_freshness,
        anchor_data.revision(),
        anchor_data.head(),
        anchor_data.projection(),
    )
    .expect("profile recovery anchor advances");
    let report = checkpoint
        .recover(fixture.catalog.clone(), fixture.limits, anchor)
        .expect("profile checkpoint recovers");
    black_box(report.acknowledged_revision());
    started.elapsed()
}

fn collect<F>(mut sample: F) -> Duration
where
    F: FnMut() -> Duration,
{
    for _ in 0..WARMUPS {
        black_box(sample());
    }
    median((0..SAMPLES).map(|_| sample()).collect())
}

fn selected_sizes() -> Vec<usize> {
    env::var("CSER_HASH_PROFILE_SIZES")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(|value| {
                    let size = value
                        .trim()
                        .parse::<usize>()
                        .unwrap_or_else(|_| panic!("invalid hash profile size: {value:?}"));
                    assert!(size > 0, "hash profile size must be non-zero");
                    size
                })
                .collect()
        })
        .unwrap_or_else(|| DEFAULT_SIZES.to_vec())
}

fn backend_name() -> &'static str {
    if cfg!(feature = "sha2-software-baseline") {
        "software-baseline"
    } else {
        "runtime-dispatch"
    }
}

fn cpu_observation() -> String {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        format!(
            "sha_ni={},sse2={},ssse3={},sse4.1={}",
            std::arch::is_x86_feature_detected!("sha"),
            std::arch::is_x86_feature_detected!("sse2"),
            std::arch::is_x86_feature_detected!("ssse3"),
            std::arch::is_x86_feature_detected!("sse4.1"),
        )
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        "non-x86-target".to_owned()
    }
}

fn main() {
    let backend = backend_name();
    let cpu = cpu_observation();
    let checkpoint = checkpoint_fixture();
    let checkpoint_bytes = checkpoint.encoded.len();
    let checkpoint_anchor = checkpoint.checkpoint.anchor();
    let fingerprint_payload = payload(4096);
    let fingerprint_digest: [u8; 32] = Sha256::digest(&fingerprint_payload).into();
    println!(
        "hash_backend_profile,backend={backend},cpu={cpu},warmups={WARMUPS},samples={SAMPLES}"
    );
    println!(
        "fingerprint,payload_bytes={},payload_sha256={},checkpoint_bytes={},checkpoint_head={},checkpoint_projection={},checkpoint_envelope={}",
        fingerprint_payload.len(),
        hex_digest(Digest::new(fingerprint_digest)),
        checkpoint_bytes,
        hex_digest(checkpoint_anchor.head()),
        hex_digest(checkpoint_anchor.projection()),
        hex_digest(checkpoint_anchor.envelope()),
    );
    println!(
        "workload,input_bytes,iterations,median_ns,hashed_bytes,throughput_mib_s,checkpoint_bytes,recovery_input_bytes"
    );

    for size in selected_sizes() {
        let input = payload(size);
        let rounds = TARGET_HASH_BYTES.div_ceil(size).max(1);
        let elapsed = collect(|| hash_rounds(&input, rounds));
        let hashed_bytes = size.saturating_mul(rounds);
        let mib_per_second = (hashed_bytes as f64 / (1024.0 * 1024.0))
            / elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
        println!(
            "hash,{size},{rounds},{},{hashed_bytes},{mib_per_second:.3},{checkpoint_bytes},{checkpoint_bytes}",
            elapsed.as_nanos()
        );
    }

    let encode_elapsed = collect(|| checkpoint_encode_sample(&checkpoint));
    println!(
        "checkpoint_encode,{checkpoint_bytes},1,{},0,0.0,{checkpoint_bytes},{checkpoint_bytes}",
        encode_elapsed.as_nanos()
    );
    let recovery_elapsed = collect(|| checkpoint_recovery_sample(&checkpoint));
    println!(
        "checkpoint_decode_recover,{checkpoint_bytes},1,{},0,0.0,{checkpoint_bytes},{checkpoint_bytes}",
        recovery_elapsed.as_nanos()
    );
}
