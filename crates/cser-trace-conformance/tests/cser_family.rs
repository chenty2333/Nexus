//! End-to-end trace conformance for the baseline `Cser` specification.
//!
//! Each test invokes the pinned TLC on a temporary copy of
//! `specs/cser/Cser.tla`, replays the resulting counterexample against
//! `cser-model`, and fails if any step or projected variable disagrees.

use std::collections::BTreeSet;

use cser_trace_conformance::cser::actions::{ALL_ACTIONS, ActionCatalog, SpecAction};
use cser_trace_conformance::cser::replay::{
    self, ConformanceError, PROJECTED_VARIABLES, UNPROJECTED_VARIABLES,
};
use cser_trace_conformance::cser::{FAMILY, WITNESSES};
use cser_trace_conformance::report::ReplayReport;
use cser_trace_conformance::tlc::WitnessRunner;
use cser_trace_conformance::{repo_root, spec_path, trace};

fn catalog() -> ActionCatalog {
    let source = std::fs::read_to_string(spec_path(FAMILY.module)).expect("Cser.tla is readable");
    ActionCatalog::from_spec_source(&source).expect("the action catalog matches Cser.tla")
}

#[test]
fn replays_every_action_label() {
    let runner = WitnessRunner::new(&repo_root()).expect("the pinned TLA+ tools are available");
    let catalog = catalog();
    let mut covered = ReplayReport::default();

    for witness in WITNESSES {
        let log = runner
            .run(&FAMILY, witness)
            .unwrap_or_else(|error| panic!("{}: {error}", witness.invariant));
        let behavior =
            trace::parse(&log).unwrap_or_else(|error| panic!("{}: {error}", witness.invariant));
        assert_eq!(behavior.invariant, witness.invariant);
        let report = replay::replay(&behavior, &catalog).unwrap_or_else(|error| {
            panic!("{} ({}): {error}", witness.invariant, witness.description)
        });

        assert_eq!(report.transitions(), behavior.transitions());
        assert!(
            report.transitions() > 0,
            "{} produced a behavior with no transitions",
            witness.invariant
        );
        covered.merge(&report);
        println!(
            "{}: {} transitions replayed ({})",
            witness.invariant,
            report.transitions(),
            witness.description
        );
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

    let uncovered: Vec<SpecAction> = ALL_ACTIONS
        .into_iter()
        .filter(|action| !covered.actions().contains_key(action.spec_name()))
        .collect();
    assert!(
        uncovered.is_empty(),
        "witnesses did not exercise every operation; missing {uncovered:?}"
    );
}

#[test]
fn projection_accounts_for_every_specification_variable() {
    let source = std::fs::read_to_string(spec_path(FAMILY.module)).expect("Cser.tla is readable");
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

#[test]
fn rejects_mutated_traces() {
    let runner = WitnessRunner::new(&repo_root()).expect("the pinned TLA+ tools are available");
    let catalog = catalog();
    let witness = &WITNESSES[0];
    let log = runner
        .run(&FAMILY, witness)
        .expect("the commit witness is refuted");
    let behavior = trace::parse(&log).expect("the counterexample parses");
    assert!(
        replay::replay(&behavior, &catalog).is_ok(),
        "the unmodified behavior must replay"
    );

    // A wrong value in the final state must be caught by the projection.
    let mut corrupted = behavior.clone();
    let last = corrupted
        .states
        .last_mut()
        .expect("the behavior has a final state");
    last.variables.insert(
        String::from("freeBudget"),
        cser_trace_conformance::value::TlaValue::Int(7),
    );
    assert!(
        matches!(
            replay::replay(&corrupted, &catalog),
            Err(ConformanceError::ProjectionMismatch {
                variable: "freeBudget",
                ..
            })
        ),
        "a corrupted variable must be rejected"
    );

    // Deleting the `prepare` step makes `commit` follow `register` directly,
    // which the oracle must refuse.
    let mut reordered = behavior.clone();
    reordered.states.remove(2);
    for (position, state) in reordered.states.iter_mut().enumerate() {
        state.index = u32::try_from(position).expect("short behavior") + 1;
    }
    assert!(
        matches!(
            replay::replay(&reordered, &catalog),
            Err(ConformanceError::Rejected {
                action: SpecAction::Commit,
                ..
            })
        ),
        "an illegal operation order must be rejected"
    );
}
