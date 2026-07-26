//! End-to-end trace conformance for the `ProductionIdentityCser` family.
//!
//! Each test invokes the pinned TLC on a temporary copy of
//! `specs/cser/ProductionIdentityCser.tla` under its released safety
//! configuration, replays the resulting counterexample against
//! `cser-model`'s production-identity oracle, and fails if any step or
//! projected variable disagrees.

use std::collections::BTreeSet;

use cser_trace_conformance::production_identity::actions::{
    ALL_ACTIONS, ActionCatalog, SpecAction,
};
use cser_trace_conformance::production_identity::replay::{
    self, ConformanceError, PROJECTED_VARIABLES, UNPROJECTED_VARIABLES,
};
use cser_trace_conformance::production_identity::{FAMILY, WITNESSES};
use cser_trace_conformance::report::ReplayReport;
use cser_trace_conformance::tlc::WitnessRunner;
use cser_trace_conformance::trace::{ActionLabel, Trace};
use cser_trace_conformance::value::TlaValue;
use cser_trace_conformance::{repo_root, spec_path, trace};

fn catalog() -> ActionCatalog {
    let source =
        std::fs::read_to_string(spec_path(FAMILY.module)).expect("the specification is readable");
    ActionCatalog::from_spec_source(&source).expect("the action catalog matches the specification")
}

fn behaviors(runner: &WitnessRunner) -> Vec<(&'static str, Trace)> {
    WITNESSES
        .iter()
        .map(|witness| {
            let log = runner
                .run(&FAMILY, witness)
                .unwrap_or_else(|error| panic!("{}: {error}", witness.invariant));
            let behavior =
                trace::parse(&log).unwrap_or_else(|error| panic!("{}: {error}", witness.invariant));
            assert_eq!(behavior.invariant, witness.invariant);
            (witness.invariant, behavior)
        })
        .collect()
}

/// Every released witness must replay every one of its transitions against
/// the oracle, and their union must exercise the family's whole event
/// vocabulary.
#[test]
fn replays_every_released_witness() {
    let runner = WitnessRunner::new(&repo_root()).expect("the pinned TLA+ tools are available");
    let catalog = catalog();
    let mut covered = ReplayReport::default();

    for (invariant, behavior) in behaviors(&runner) {
        assert!(
            matches!(behavior.states[0].action, ActionLabel::Initial),
            "{invariant} does not start at an initial state"
        );
        let resolved = replay::replay(&behavior, &catalog)
            .unwrap_or_else(|error| panic!("{invariant}: {error}"));
        assert_eq!(resolved.transitions(), behavior.transitions());
        println!(
            "{invariant}: {} transitions replayed",
            resolved.transitions()
        );
        covered.merge(&resolved);
    }

    println!(
        "replayed {} traces, {} transitions total",
        WITNESSES.len(),
        covered.transitions()
    );
    for action in ALL_ACTIONS {
        println!(
            "  {action}: {}",
            covered
                .actions()
                .get(action.spec_name())
                .copied()
                .unwrap_or(0)
        );
    }
    let uncovered: Vec<&str> = ALL_ACTIONS
        .into_iter()
        .map(|action| action.spec_name())
        .filter(|name| !covered.actions().contains_key(name))
        .collect();
    assert!(
        uncovered.is_empty(),
        "released witnesses did not exercise every event; missing {uncovered:?}"
    );
}

#[test]
fn projection_accounts_for_every_specification_variable() {
    let source =
        std::fs::read_to_string(spec_path(FAMILY.module)).expect("the specification is readable");
    let declared: BTreeSet<&str> = source
        .lines()
        .find(|line| line.starts_with("VARIABLES "))
        .expect("the translation declares its variables")
        .trim_start_matches("VARIABLES ")
        .split(',')
        .map(str::trim)
        .collect();

    let accounted: BTreeSet<&str> = PROJECTED_VARIABLES
        .into_iter()
        .chain(UNPROJECTED_VARIABLES)
        .collect();
    assert_eq!(
        declared, accounted,
        "the projection must classify every specification variable as projected or not"
    );
}

/// The replayer must be able to fail. Each mutation below targets a different
/// mechanism: the projection, the oracle's guards, the catalog's three-way
/// corroboration, and the desynchronized-window accounting.
#[test]
fn rejects_mutated_traces() {
    let runner = WitnessRunner::new(&repo_root()).expect("the pinned TLA+ tools are available");
    let catalog = catalog();
    let witness = &WITNESSES[0];
    let log = runner
        .run(&FAMILY, witness)
        .expect("the identity-preserving witness is refuted");
    let behavior = trace::parse(&log).expect("the counterexample parses");
    assert!(
        replay::replay(&behavior, &catalog).is_ok(),
        "the unmodified behavior must replay"
    );

    // A wrong value in a projected variable must be caught by the projection.
    let mut corrupted = behavior.clone();
    corrupted
        .states
        .last_mut()
        .expect("the behavior has a final state")
        .variables
        .insert(String::from("crashCount"), TlaValue::Int(9));
    assert!(
        matches!(
            replay::replay(&corrupted, &catalog),
            Err(ConformanceError::ProjectionMismatch {
                variable: "crashCount",
                ..
            })
        ),
        "a corrupted projected variable must be rejected"
    );

    // Deleting `DeviceComplete` makes `IotlbAck` follow the commit directly,
    // which the oracle must refuse because no backend result exists yet.
    let position = index_of(&behavior, "DeviceComplete");
    let mut reordered = behavior.clone();
    reordered.states.remove(position);
    renumber(&mut reordered);
    assert!(
        matches!(
            replay::replay(&reordered, &catalog),
            Err(ConformanceError::Rejected {
                action: SpecAction::IotlbAck,
                ..
            })
        ),
        "an illegal operation order must be rejected"
    );

    // Rewriting the recorded actor class must break the catalog's
    // corroboration between the event, the process, and the actor.
    let mut relabelled = behavior.clone();
    relabelled.states[index_of(&behavior, "Derive")]
        .variables
        .insert(
            String::from("lastActorKind"),
            TlaValue::Str(String::from("Irq")),
        );
    assert!(
        matches!(
            replay::replay(&relabelled, &catalog),
            Err(ConformanceError::Catalog(_))
        ),
        "a mislabelled actor class must be rejected"
    );

    // Dropping one `CompleteDma` leaves the specification permanently behind
    // the oracle's atomic acknowledgement, which the window must report.
    let mut truncated = behavior.clone();
    truncated.states.remove(index_of(&behavior, "CompleteDma"));
    renumber(&mut truncated);
    assert!(
        matches!(
            replay::replay(&truncated, &catalog),
            Err(ConformanceError::UnresolvedDesynchronization { .. })
                | Err(ConformanceError::Operand { .. })
        ),
        "an unreconciled terminalization must be rejected"
    );
}

/// Returns the index of the first state whose recorded event is `event`.
fn index_of(behavior: &Trace, event: &str) -> usize {
    behavior
        .states
        .iter()
        .position(|state| state.get("lastEvent") == Some(&TlaValue::Str(String::from(event))))
        .unwrap_or_else(|| panic!("the behavior contains a {event} step"))
}

fn renumber(behavior: &mut Trace) {
    for (position, state) in behavior.states.iter_mut().enumerate() {
        state.index = u32::try_from(position).expect("short behavior") + 1;
    }
}
