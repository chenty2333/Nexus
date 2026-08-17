//! Production-path transition profile for the provider-generation CSER core.
//!
//! This example intentionally uses only the public scoped API and is built
//! without `full-invariant-oracle`.  It reports structural measurements, not
//! a general performance claim.  For each `N`, one fixture contains `N`
//! unrelated records plus two fixed groups of eight targets: one group for
//! logical claim adds and one for provider fences.  Fixture setup is timed
//! separately and shared by all measured workloads.
//!
//! By default the CSV contains `N = 1,64,512,4096`.  Select one or more sizes
//! with `CSER_PROFILE_N=4096`, `CSER_PROFILE_SIZES=4096`, `--n 4096`,
//! `--n=4096`, or a positional `4096` argument.  Comma-separated sizes are
//! accepted for either environment variable or CLI form.
//! Run it with `cargo run --release --no-default-features -p cser-core
//! --example cser_transition_profile`; the example refuses to publish timing
//! rows while the test-only full invariant oracle is enabled.

use std::env;
use std::hint::black_box;
use std::time::Instant;

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, BootGeneration,
    CatalogSet, ClaimId, ClaimScope, CommandRequest, ComponentProviderBinding, CoreLimits,
    DeviceGeneration, Digest, Engine, ExecutorCoordinate, ExecutorGeneration, ExecutorId,
    Freshness, JournalGeneration, OperationId, ProviderCoordinate, ProviderEffectState,
    ProviderGeneration, ProviderId, RegistryInstance, ResourceGeneration, ResourceId,
    VerifierBinding, VerifierGeneration, WorldId, standard_catalog,
};

const WORLD: u64 = 1;
const PROVIDER_BASE: u64 = 10_000;
const OPERATION_BASE: u64 = 20_000;
const ACTOR_BASE: u64 = 30_000;

const DEFAULT_SIZES: [usize; 4] = [1, 64, 512, 4096];
const TARGETS: usize = 8;
const PROJECTION_READS: usize = 100_000;

#[derive(Clone, Copy)]
struct Target {
    provider: ProviderCoordinate,
    effect: cser_core::EffectId,
    actor: ExecutorCoordinate,
    ordinal: u64,
}

struct Fixture {
    engine: Engine,
    logical_claim_targets: Vec<Target>,
    provider_fence_targets: Vec<Target>,
}

fn transact(engine: &mut Engine, command: CommandRequest) {
    engine
        .transact(command, |_| Ok::<(), core::convert::Infallible>(()))
        .expect("in-memory production transition succeeds");
}

fn freshness() -> Freshness {
    Freshness::new(
        BootGeneration::new(1).expect("non-zero boot"),
        RegistryInstance::new(1).expect("non-zero registry"),
        DeviceGeneration::new(1).expect("non-zero device"),
        JournalGeneration::new(1).expect("non-zero journal"),
    )
}

fn limits(n: usize) -> CoreLimits {
    CoreLimits::new(n + 8, n + 8, n + 8, n + 8, 4, 1 << 20, 1024).expect("valid profile limits")
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
    let target_records = TARGETS.checked_mul(2).expect("target count fits");
    let record_count = n.checked_add(target_records).expect("fixture size fits");
    let catalog_set = CatalogSet::new(std::slice::from_ref(&catalog)).expect("valid catalog set");
    let mut engine = Engine::new(world, catalog_set, limits(record_count), freshness());
    let mut logical_claim_targets = Vec::with_capacity(TARGETS);
    let mut provider_fence_targets = Vec::with_capacity(TARGETS);

    for index in 0..record_count {
        let ordinal = index as u64;
        let provider = ProviderCoordinate::new(
            world,
            ProviderId::new(PROVIDER_BASE + ordinal).expect("provider id fits"),
            ProviderGeneration::new(1).expect("non-zero provider generation"),
        );
        transact(
            &mut engine,
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
        let target = Target {
            provider,
            effect,
            actor,
            ordinal,
        };
        if index < TARGETS {
            logical_claim_targets.push(target);
        } else if index < target_records {
            provider_fence_targets.push(target);
        }
    }

    assert_eq!(
        engine.revision(),
        (2 * record_count) as u64,
        "fixture setup must advance exactly once for registration and admission"
    );
    assert_eq!(logical_claim_targets.len(), TARGETS);
    assert_eq!(provider_fence_targets.len(), TARGETS);
    Fixture {
        engine,
        logical_claim_targets,
        provider_fence_targets,
    }
}

fn ns_per_op(elapsed: std::time::Duration, iterations: usize) -> f64 {
    elapsed.as_nanos() as f64 / iterations as f64
}

fn print_row(workload: &str, n: usize, iterations: usize, ns: f64) {
    println!("{workload},{n},{iterations},{ns:.3}");
}

fn profile_logical_claim(fixture: &mut Fixture) -> f64 {
    let measured_start = Instant::now();
    for target in &fixture.logical_claim_targets {
        transact(
            &mut fixture.engine,
            CommandRequest::AddComponentClaim {
                effect: target.effect,
                component: AGENT_COMPONENT_REPLY,
                actor: target.actor,
                claim: ClaimId::new(OPERATION_BASE + target.ordinal).expect("claim id fits"),
                kind: cser_core::REPLY_CLAIM_PUBLICATION_SLOT,
                scope: ClaimScope::Logical,
                resource: ResourceId::new(OPERATION_BASE + target.ordinal)
                    .expect("resource id fits"),
                resource_generation: ResourceGeneration::new(1)
                    .expect("non-zero resource generation"),
                units: 1,
            },
        );
    }
    let elapsed = measured_start.elapsed();
    let touched_state = fixture
        .logical_claim_targets
        .iter()
        .filter(|target| {
            fixture
                .engine
                .component_claims(target.effect, AGENT_COMPONENT_REPLY)
                .expect("target component exists")
                .len()
                == 1
        })
        .count();
    assert_eq!(
        touched_state, TARGETS,
        "logical claim workload touched state"
    );
    ns_per_op(elapsed, TARGETS)
}

fn profile_provider_fence(fixture: &mut Fixture) -> f64 {
    let measured_start = Instant::now();
    for target in &fixture.provider_fence_targets {
        transact(
            &mut fixture.engine,
            CommandRequest::FenceProviderEffects {
                coordinate: target.provider,
                expected_epoch: 1,
            },
        );
    }
    let elapsed = measured_start.elapsed();
    let touched_state = fixture
        .provider_fence_targets
        .iter()
        .filter(|target| {
            matches!(
                fixture
                    .engine
                    .provider_generation_projection(target.provider)
                    .expect("target provider exists")
                    .state,
                ProviderEffectState::EffectFenced { epoch: 2 }
            )
        })
        .count();
    assert_eq!(
        touched_state, TARGETS,
        "provider fence workload touched state"
    );
    ns_per_op(elapsed, TARGETS)
}

fn profile_projection_reads(fixture: &Fixture) -> f64 {
    let measured_start = Instant::now();
    let mut nonzero_reads = 0usize;
    for _ in 0..PROJECTION_READS {
        let digest = black_box(fixture.engine.projection_digest());
        nonzero_reads += usize::from(!digest.is_zero());
        black_box(nonzero_reads);
    }
    let elapsed = measured_start.elapsed();
    assert_eq!(nonzero_reads, PROJECTION_READS);
    ns_per_op(elapsed, PROJECTION_READS)
}

fn profile_n(n: usize) {
    // Setup is deliberately outside every workload measurement and happens
    // once for this N.  The fixed target groups keep the measured transition
    // count independent of the amount of unrelated fixture state.
    let setup_start = Instant::now();
    let mut fixture = fixture(n);
    let setup_elapsed = setup_start.elapsed();
    let setup_revision = fixture.engine.revision();

    // Read the projection before mutating either target group so this fixed
    // read workload remains independent of the transition workloads.
    let projection_ns = profile_projection_reads(&fixture);
    assert_eq!(fixture.engine.revision(), setup_revision);
    let logical_claim_ns = profile_logical_claim(&mut fixture);
    let provider_fence_ns = profile_provider_fence(&mut fixture);
    assert_eq!(
        fixture.engine.revision(),
        setup_revision + (2 * TARGETS) as u64,
        "only the fixed target groups may advance the workload revision"
    );

    print_row("fixture_setup", n, 1, setup_elapsed.as_nanos() as f64);
    print_row("logical_claim_add", n, TARGETS, logical_claim_ns);
    print_row("provider_fence", n, TARGETS, provider_fence_ns);
    print_row("projection_digest_read", n, PROJECTION_READS, projection_ns);
}

fn parse_sizes(raw: &str) -> Vec<usize> {
    let sizes: Vec<usize> = raw
        .split(',')
        .map(|value| {
            let n = value
                .trim()
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("invalid profile N: {value:?}"));
            assert!(n > 0, "profile N must be non-zero");
            n
        })
        .collect();
    assert!(!sizes.is_empty(), "profile N selection must not be empty");
    sizes
}

fn selected_sizes() -> Vec<usize> {
    let mut cli_selection = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--n=") {
            cli_selection = Some(value.to_owned());
        } else if arg == "--n" {
            cli_selection = Some(args.next().expect("--n requires a value"));
        } else if arg == "--help" || arg == "-h" {
            println!("usage: cser_transition_profile [--n N | N]");
            println!("       CSER_PROFILE_N=N cser_transition_profile");
            println!("       N may be a comma-separated list");
            std::process::exit(0);
        } else if !arg.starts_with('-') {
            cli_selection = Some(arg);
        } else {
            panic!("unknown option {arg:?}; use --help for usage");
        }
    }

    cli_selection
        .or_else(|| env::var("CSER_PROFILE_N").ok())
        .or_else(|| env::var("CSER_PROFILE_SIZES").ok())
        .map(|raw| parse_sizes(&raw))
        .unwrap_or_else(|| DEFAULT_SIZES.to_vec())
}

fn main() {
    if cfg!(feature = "full-invariant-oracle") {
        eprintln!(
            "cser_transition_profile requires the production transition gate; \
             rerun with --no-default-features"
        );
        std::process::exit(2);
    }
    println!("workload,N,iterations,ns_per_op");
    for n in selected_sizes() {
        profile_n(n);
    }
}
