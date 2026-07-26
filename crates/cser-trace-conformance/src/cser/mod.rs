//! The baseline `Cser` specification family.
//!
//! `Cser.tla` releases no reachability witnesses of its own, so this family
//! supplies witness invariants in a generated module that extends it. The
//! generated definitions are the only TLA+ text this lane authors; the
//! specification and its configuration are used as released.

pub mod actions;
pub mod replay;

use crate::tlc::{FamilySpec, Witness};

/// Reachability witnesses whose refutations this lane replays.
///
/// Each definition names a state the baseline specification must be able to
/// reach; TLC's counterexample is the shortest behavior that reaches it. The
/// witnesses are chosen so that their union exercises every operation of
/// `Cser.tla`.
pub const WITNESSES: &[Witness] = &[
    Witness {
        invariant: "CommitAbsent",
        definition: Some("CommitAbsent == \\A e \\in Effects : effectState[e] # \"Committed\""),
        constraint: None,
        description: "an effect crosses its commit point",
    },
    Witness {
        invariant: "CompletionAbsent",
        definition: Some("CompletionAbsent == \\A e \\in Effects : effectState[e] # \"Completed\""),
        constraint: None,
        description: "a committed effect completes normally",
    },
    Witness {
        invariant: "EmptyClosureAbsent",
        definition: Some("EmptyClosureAbsent == scopeState # \"Revoked\""),
        constraint: None,
        description: "revocation opens and closes with no live effect",
    },
    Witness {
        invariant: "AbortClosureAbsent",
        definition: Some(
            "AbortClosureAbsent ==\n    ~(scopeState = \"Revoked\"\n      /\\ \\E e \\in Effects : effectState[e] = \"Aborted\")",
        ),
        constraint: None,
        description: "an uncommitted effect cancels, aborts, and returns its credit before closure",
    },
    Witness {
        invariant: "DrainAbsent",
        definition: Some("DrainAbsent == \\A e \\in Effects : effectState[e] # \"Draining\""),
        constraint: None,
        description: "revocation wins after a commit and drains instead of cancelling",
    },
    Witness {
        invariant: "RebindAbsent",
        definition: Some("RebindAbsent == ~(bindingEpoch > 0 /\\ supervisorAlive)"),
        constraint: None,
        description: "a crash fences the binding, fallback runs, and a replacement binds",
    },
    Witness {
        invariant: "AdoptAbsent",
        definition: Some(
            "AdoptAbsent ==\n    \\A e \\in Effects :\n        ~(/\\ effectState[e] \\in {\"Registered\", \"Prepared\"}\n          /\\ effectBinding[e] = bindingEpoch\n          /\\ bindingEpoch > 0)\n\nAdoptScenario == bindingEpoch = 0 \\/ freeBudget = 0",
        ),
        // Without this constraint the shortest behavior reaching the witness
        // registers a fresh effect after the rebind instead of adopting an
        // orphan. Exhausting the budget before any crash forces adoption.
        constraint: Some("AdoptScenario"),
        description: "an orphan uncommitted effect is explicitly adopted by the replacement",
    },
];

/// The family descriptor used to drive TLC.
pub const FAMILY: FamilySpec = FamilySpec {
    module: "Cser",
    base_config: "CserMC.cfg",
    witnesses: WITNESSES,
};
