//! Resolution of `ProductionIdentityCser` transitions to protocol events.
//!
//! # Why this family needs a different discriminator
//!
//! In `Cser.tla` the translated `Environment` operator is a top-level
//! disjunction, so TLC attributes each trace state to the individual disjunct
//! and prints its source line range. `ProductionIdentityCser`'s translation
//! instead reads `Environment == /\ \/ ... /\ UNCHANGED <<...>>`: the
//! top-level operator is a conjunction, so TLC prints one line range spanning
//! the whole definition for every environment step. The action label
//! therefore identifies only the *process*, not the operation.
//!
//! The specification does record the operation: every branch assigns the
//! ghost variable `lastEvent`, drawn from the vocabulary the module declares
//! as `ServiceEvents`, `KernelEvents`, and `IrqEvents`. This catalog resolves
//! transitions through that variable and keeps the action label as a
//! corroborating check on which process ran.
//!
//! # Fail-loud derivation
//!
//! Nothing here is hard-coded to the current text beyond the event names
//! themselves. Catalog construction reads the specification and requires
//! three independently derived orderings to agree:
//!
//! 1. the `lastEvent := "..."` assignments of the PlusCal algorithm, in
//!    source order and partitioned by process;
//! 2. the `lastEvent' = "..."` conjuncts of the checked-in translation, in
//!    source order and partitioned by translated definition;
//! 3. the declared `ServiceEvents` / `KernelEvents` / `IrqEvents` sets,
//!    cross-checked against the `lastActorKind := "..."` assignment that
//!    follows each event in the PlusCal source.
//!
//! Any spec edit that adds, removes, renames, or moves an event breaks at
//! least one of the three and fails construction rather than mis-mapping a
//! replayed behavior.

use core::fmt;
use std::collections::BTreeMap;

use crate::trace::{ActionLabel, TraceState};
use crate::value::{self, TlaValue};

/// One atomic protocol event of `ProductionIdentityCser`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SpecAction {
    /// Workload derivation of the next effect in `DeriveOrder`.
    Derive,
    /// Preparation of the next derived effect.
    Prepare,
    /// Filesystem service crash; advances only that domain's binding.
    Crash,
    /// Recovery snapshot of the crashed domain's cohort.
    Snapshot,
    /// Replacement service reports readiness.
    Ready,
    /// Replacement service is installed in the domain binding.
    Rebind,
    /// Explicit adoption of an orphan effect by the replacement.
    Adopt,
    /// Device batch commit: the block request crosses its commit point.
    DeviceCommit,
    /// Backend completion published by the device IRQ path.
    DeviceComplete,
    /// Device reset timeout retains the effect under a tombstone.
    ResetTimeout,
    /// Retry issued after a reset timeout.
    ResetRetry,
    /// Reset acknowledgement from the device IRQ path.
    ResetAck,
    /// IOTLB timeout retains the effect under a tombstone.
    IotlbTimeout,
    /// Retry issued after an IOTLB timeout.
    IotlbRetry,
    /// IOTLB acknowledgement from the device IRQ path.
    IotlbAck,
    /// A foreign-registry input is rejected without semantic mutation.
    RejectForeign,
    /// A stale device generation is rejected without semantic mutation.
    RejectStaleGeneration,
    /// The revocation linearization point at the shared root gate.
    RevokeBegin,
    /// Terminalization of a committed DMA owner.
    CompleteDma,
    /// Terminalization of the committed block request.
    CompleteBlock,
    /// Terminalization of the committed filesystem read.
    CompleteFilesystem,
    /// Publication of the guest reply.
    GuestReply,
    /// Abort of an uncommitted leaf during closure.
    AbortLeaf,
    /// Publication of one domain's closure receipt.
    DomainReceipt,
    /// Quiescent closure acknowledgement.
    RevokeComplete,
}

/// Which translated definition owns an event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Process {
    /// The `Environment` process, driven by the workload and device paths.
    Environment,
    /// The `Kernel` process, which carries the weak-fairness obligation.
    Kernel,
}

impl Process {
    /// Returns the translated definition name TLC prints for this process.
    #[must_use]
    pub const fn definition(self) -> &'static str {
        match self {
            Self::Environment => "Environment",
            Self::Kernel => "Kernel",
        }
    }
}

/// The actor class the specification attributes to an event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorKind {
    /// A user-space service instance.
    Service,
    /// The kernel.
    Kernel,
    /// The device interrupt path.
    Irq,
}

impl ActorKind {
    /// Returns the `lastActorKind` string the specification assigns.
    #[must_use]
    pub const fn spec_name(self) -> &'static str {
        match self {
            Self::Service => "Service",
            Self::Kernel => "Kernel",
            Self::Irq => "Irq",
        }
    }

    /// Returns the name of the declared event set for this actor class.
    const fn declared_set(self) -> &'static str {
        match self {
            Self::Service => "ServiceEvents",
            Self::Kernel => "KernelEvents",
            Self::Irq => "IrqEvents",
        }
    }
}

impl SpecAction {
    /// Returns the event name the specification assigns to `lastEvent`.
    #[must_use]
    pub const fn spec_name(self) -> &'static str {
        match self {
            Self::Derive => "Derive",
            Self::Prepare => "Prepare",
            Self::Crash => "Crash",
            Self::Snapshot => "Snapshot",
            Self::Ready => "Ready",
            Self::Rebind => "Rebind",
            Self::Adopt => "Adopt",
            Self::DeviceCommit => "DeviceCommit",
            Self::DeviceComplete => "DeviceComplete",
            Self::ResetTimeout => "ResetTimeout",
            Self::ResetRetry => "ResetRetry",
            Self::ResetAck => "ResetAck",
            Self::IotlbTimeout => "IotlbTimeout",
            Self::IotlbRetry => "IotlbRetry",
            Self::IotlbAck => "IotlbAck",
            Self::RejectForeign => "RejectForeign",
            Self::RejectStaleGeneration => "RejectStaleGeneration",
            Self::RevokeBegin => "RevokeBegin",
            Self::CompleteDma => "CompleteDma",
            Self::CompleteBlock => "CompleteBlock",
            Self::CompleteFilesystem => "CompleteFilesystem",
            Self::GuestReply => "GuestReply",
            Self::AbortLeaf => "AbortLeaf",
            Self::DomainReceipt => "DomainReceipt",
            Self::RevokeComplete => "RevokeComplete",
        }
    }
}

impl fmt::Display for SpecAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.spec_name())
    }
}

/// Every event this lane knows how to resolve, in specification order.
pub const ALL_ACTIONS: [SpecAction; 25] = [
    SpecAction::Derive,
    SpecAction::Prepare,
    SpecAction::Crash,
    SpecAction::Snapshot,
    SpecAction::Ready,
    SpecAction::Rebind,
    SpecAction::Adopt,
    SpecAction::DeviceCommit,
    SpecAction::DeviceComplete,
    SpecAction::ResetTimeout,
    SpecAction::ResetRetry,
    SpecAction::ResetAck,
    SpecAction::IotlbTimeout,
    SpecAction::IotlbRetry,
    SpecAction::IotlbAck,
    SpecAction::RejectForeign,
    SpecAction::RejectStaleGeneration,
    SpecAction::RevokeBegin,
    SpecAction::CompleteDma,
    SpecAction::CompleteBlock,
    SpecAction::CompleteFilesystem,
    SpecAction::GuestReply,
    SpecAction::AbortLeaf,
    SpecAction::DomainReceipt,
    SpecAction::RevokeComplete,
];

const EVENT_VARIABLE: &str = "lastEvent";
const ACTOR_VARIABLE: &str = "lastActorKind";
const ALGORITHM_START: &str = "process Environment = \"environment\"";
const KERNEL_PROCESS: &str = "fair process Kernel = \"kernel\"";
const ALGORITHM_END: &str = "end algorithm;";
const ENVIRONMENT_DEFINITION: &str = "Environment ==";
const KERNEL_DEFINITION: &str = "Kernel ==";
const NEXT_DEFINITION: &str = "Next ==";

/// Rejected specification source or trace state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogError {
    /// A required source anchor was absent.
    MissingAnchor {
        /// Text the catalog searched for.
        anchor: &'static str,
    },
    /// The PlusCal source and its translation disagree about the events of a
    /// process, or about their order.
    OrderingMismatch {
        /// Process whose orderings disagree.
        process: Process,
        /// Events found in the PlusCal algorithm, in order.
        algorithm: Vec<String>,
        /// Events found in the translation, in order.
        translation: Vec<String>,
    },
    /// An event name is not one this lane models.
    UnknownEvent {
        /// Event name found.
        event: String,
    },
    /// The declared event-class sets do not match the actor kinds the
    /// algorithm assigns.
    ActorClassMismatch {
        /// Event whose classification disagrees.
        event: String,
        /// Actor kind assigned beside the event.
        assigned: String,
        /// Declared set that contains the event, if any.
        declared: Option<String>,
    },
    /// A declared event-class set was missing or unparsable.
    MalformedEventSet {
        /// Set name.
        set: &'static str,
    },
    /// An event was assigned in the algorithm without an actor kind.
    MissingActorKind {
        /// Event name.
        event: String,
    },
    /// A trace state did not record a resolvable event.
    MissingEvent {
        /// State index.
        state_index: u32,
    },
    /// The action label named a definition that does not own the event.
    ProcessMismatch {
        /// State index.
        state_index: u32,
        /// Event recorded in the state.
        event: SpecAction,
        /// Definition the event belongs to.
        expected: &'static str,
        /// Definition TLC printed.
        found: String,
    },
    /// The state's actor kind disagrees with the specification's declaration.
    ActorMismatch {
        /// State index.
        state_index: u32,
        /// Event recorded in the state.
        event: SpecAction,
        /// Actor kind the catalog derived.
        expected: &'static str,
        /// Actor kind the state recorded.
        found: String,
    },
    /// The initial state was used where a transition was required.
    InitialState,
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAnchor { anchor } => {
                write!(
                    formatter,
                    "ProductionIdentityCser.tla does not contain {anchor:?}"
                )
            }
            Self::OrderingMismatch {
                process,
                algorithm,
                translation,
            } => write!(
                formatter,
                "{} events disagree between algorithm {algorithm:?} and translation \
                 {translation:?}",
                process.definition()
            ),
            Self::UnknownEvent { event } => {
                write!(formatter, "specification names unmodelled event {event}")
            }
            Self::ActorClassMismatch {
                event,
                assigned,
                declared,
            } => write!(
                formatter,
                "event {event} is assigned actor kind {assigned} but is declared in {declared:?}"
            ),
            Self::MalformedEventSet { set } => {
                write!(
                    formatter,
                    "declared event set {set} is missing or unparsable"
                )
            }
            Self::MissingActorKind { event } => {
                write!(formatter, "event {event} has no actor kind assignment")
            }
            Self::MissingEvent { state_index } => write!(
                formatter,
                "state {state_index} records no resolvable {EVENT_VARIABLE}"
            ),
            Self::ProcessMismatch {
                state_index,
                event,
                expected,
                found,
            } => write!(
                formatter,
                "state {state_index}: {event} belongs to {expected} but TLC attributed it to \
                 {found}"
            ),
            Self::ActorMismatch {
                state_index,
                event,
                expected,
                found,
            } => write!(
                formatter,
                "state {state_index}: {event} is a {expected} event but the state recorded {found}"
            ),
            Self::InitialState => formatter.write_str("the initial state has no protocol event"),
        }
    }
}

impl std::error::Error for CatalogError {}

/// What the specification declares about one event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventFacts {
    /// Translated definition that contains the event.
    pub process: Process,
    /// Actor class the specification attributes to the event.
    pub actor: ActorKind,
}

/// Mapping from recorded events to their specification facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionCatalog {
    events: BTreeMap<SpecAction, EventFacts>,
}

impl ActionCatalog {
    /// Derives the catalog from the text of
    /// `specs/cser/ProductionIdentityCser.tla`.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] when the three derived orderings disagree, or
    /// when the specification names an event this lane does not model.
    pub fn from_spec_source(source: &str) -> Result<Self, CatalogError> {
        let lines: Vec<&str> = source.lines().collect();

        let algorithm_start = find(&lines, ALGORITHM_START)?;
        let kernel_process = find(&lines, KERNEL_PROCESS)?;
        let algorithm_end = find_prefix(&lines, ALGORITHM_END)?;
        let environment_definition = find_prefix(&lines, ENVIRONMENT_DEFINITION)?;
        let kernel_definition = find_prefix(&lines, KERNEL_DEFINITION)?;
        let next_definition = find_prefix(&lines, NEXT_DEFINITION)?;

        let assignments = [
            (
                Process::Environment,
                assigned_events(&lines[algorithm_start..kernel_process], ":="),
                assigned_events(&lines[environment_definition..kernel_definition], "' ="),
            ),
            (
                Process::Kernel,
                assigned_events(&lines[kernel_process..algorithm_end], ":="),
                assigned_events(&lines[kernel_definition..next_definition], "' ="),
            ),
        ];

        let mut events = BTreeMap::new();
        for (process, algorithm, translation) in assignments {
            if algorithm != translation || algorithm.is_empty() {
                return Err(CatalogError::OrderingMismatch {
                    process,
                    algorithm,
                    translation,
                });
            }
            for event in algorithm {
                let action = action_named(&event)?;
                events.insert(action, process);
            }
        }

        let actors = declared_actor_kinds(source)?;
        let assigned = assigned_actor_kinds(&lines[algorithm_start..algorithm_end])?;

        let mut catalog = BTreeMap::new();
        for (action, process) in events {
            let assigned_actor =
                assigned
                    .get(&action)
                    .ok_or_else(|| CatalogError::MissingActorKind {
                        event: String::from(action.spec_name()),
                    })?;
            let declared_actor = actors.get(&action).copied();
            if declared_actor != Some(*assigned_actor) {
                return Err(CatalogError::ActorClassMismatch {
                    event: String::from(action.spec_name()),
                    assigned: String::from(assigned_actor.spec_name()),
                    declared: declared_actor.map(|actor| String::from(actor.declared_set())),
                });
            }
            catalog.insert(
                action,
                EventFacts {
                    process,
                    actor: *assigned_actor,
                },
            );
        }

        for action in ALL_ACTIONS {
            if !catalog.contains_key(&action) {
                return Err(CatalogError::UnknownEvent {
                    event: String::from(action.spec_name()),
                });
            }
        }
        Ok(Self { events: catalog })
    }

    /// Resolves the event that produced a trace state, corroborating it
    /// against the process TLC attributed the step to and the actor kind the
    /// state recorded.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for the initial state, for unmodelled events,
    /// and whenever the recorded event, the printed definition, and the
    /// recorded actor kind do not agree.
    pub fn resolve(&self, state: &TraceState) -> Result<SpecAction, CatalogError> {
        let ActionLabel::Definition { name, .. } = &state.action else {
            return Err(CatalogError::InitialState);
        };
        let event = match state.get(EVENT_VARIABLE) {
            Some(TlaValue::Str(event)) => event.clone(),
            _ => {
                return Err(CatalogError::MissingEvent {
                    state_index: state.index,
                });
            }
        };
        let action = action_named(&event)?;
        let facts = self
            .events
            .get(&action)
            .ok_or(CatalogError::UnknownEvent { event })?;

        if name != facts.process.definition() {
            return Err(CatalogError::ProcessMismatch {
                state_index: state.index,
                event: action,
                expected: facts.process.definition(),
                found: name.clone(),
            });
        }
        match state.get(ACTOR_VARIABLE) {
            Some(TlaValue::Str(actor)) if actor == facts.actor.spec_name() => {}
            other => {
                return Err(CatalogError::ActorMismatch {
                    state_index: state.index,
                    event: action,
                    expected: facts.actor.spec_name(),
                    found: other.map_or_else(|| String::from("nothing"), TlaValue::to_string),
                });
            }
        }
        Ok(action)
    }

    /// Returns what the specification declares about `action`.
    #[must_use]
    pub fn facts(&self, action: SpecAction) -> Option<EventFacts> {
        self.events.get(&action).copied()
    }
}

fn action_named(event: &str) -> Result<SpecAction, CatalogError> {
    ALL_ACTIONS
        .into_iter()
        .find(|action| action.spec_name() == event)
        .ok_or_else(|| CatalogError::UnknownEvent {
            event: String::from(event),
        })
}

/// Collects the string literals assigned to `lastEvent`, in source order.
///
/// `operator` distinguishes the PlusCal form `lastEvent := "X"` from the
/// translated form `lastEvent' = "X"`.
fn assigned_events(lines: &[&str], operator: &str) -> Vec<String> {
    let marker = format!("{EVENT_VARIABLE}{operator} ");
    lines
        .iter()
        .filter_map(|line| quoted_after(line, &marker))
        .collect()
}

/// Pairs each event with the actor kind assigned beside it.
fn assigned_actor_kinds(lines: &[&str]) -> Result<BTreeMap<SpecAction, ActorKind>, CatalogError> {
    let event_marker = format!("{EVENT_VARIABLE}:= ");
    let actor_marker = format!("{ACTOR_VARIABLE}:= ");
    let mut pairs = BTreeMap::new();
    let mut pending: Option<SpecAction> = None;
    for line in lines {
        if let Some(event) = quoted_after(line, &event_marker) {
            pending = Some(action_named(&event)?);
            continue;
        }
        if let Some(actor) = quoted_after(line, &actor_marker) {
            let Some(action) = pending.take() else {
                continue;
            };
            let kind = match actor.as_str() {
                "Service" => ActorKind::Service,
                "Kernel" => ActorKind::Kernel,
                "Irq" => ActorKind::Irq,
                _ => {
                    return Err(CatalogError::ActorClassMismatch {
                        event: String::from(action.spec_name()),
                        assigned: actor,
                        declared: None,
                    });
                }
            };
            pairs.insert(action, kind);
        }
    }
    if let Some(action) = pending {
        return Err(CatalogError::MissingActorKind {
            event: String::from(action.spec_name()),
        });
    }
    Ok(pairs)
}

/// Reads the declared `ServiceEvents` / `KernelEvents` / `IrqEvents` sets.
fn declared_actor_kinds(source: &str) -> Result<BTreeMap<SpecAction, ActorKind>, CatalogError> {
    let mut declared = BTreeMap::new();
    for kind in [ActorKind::Service, ActorKind::Kernel, ActorKind::Irq] {
        let set = kind.declared_set();
        let text = definition_text(source, set).ok_or(CatalogError::MalformedEventSet { set })?;
        let TlaValue::Set(members) =
            value::parse(&text).map_err(|_| CatalogError::MalformedEventSet { set })?
        else {
            return Err(CatalogError::MalformedEventSet { set });
        };
        for member in members {
            let TlaValue::Str(event) = member else {
                return Err(CatalogError::MalformedEventSet { set });
            };
            declared.insert(action_named(&event)?, kind);
        }
    }
    Ok(declared)
}

/// Extracts the right-hand side of `name == ...`, following continuation
/// lines until the set literal's braces balance.
fn definition_text(source: &str, name: &str) -> Option<String> {
    let mut lines = source.lines();
    let head = lines.find(|line| line.starts_with(&format!("{name} ==")))?;
    let mut text = String::from(head.split_once("==")?.1.trim());
    while balance(&text) != 0 {
        text.push(' ');
        text.push_str(lines.next()?.trim());
    }
    Some(text)
}

fn balance(text: &str) -> i32 {
    text.chars().fold(0, |depth, character| match character {
        '{' => depth + 1,
        '}' => depth - 1,
        _ => depth,
    })
}

/// Returns the string literal that follows `marker`, ignoring whitespace
/// between the variable name and the assignment operator.
fn quoted_after(line: &str, marker: &str) -> Option<String> {
    let squeezed: String = line.split_whitespace().collect::<Vec<_>>().join(" ");
    let normalized = squeezed.replace(" :=", ":=");
    let rest = normalized.split_once(marker)?.1;
    let literal = rest.strip_prefix('"')?;
    let end = literal.find('"')?;
    Some(String::from(&literal[..end]))
}

fn find(lines: &[&str], anchor: &'static str) -> Result<usize, CatalogError> {
    lines
        .iter()
        .position(|line| line.trim() == anchor)
        .ok_or(CatalogError::MissingAnchor { anchor })
}

fn find_prefix(lines: &[&str], anchor: &'static str) -> Result<usize, CatalogError> {
    lines
        .iter()
        .position(|line| line.starts_with(anchor))
        .ok_or(CatalogError::MissingAnchor { anchor })
}

#[cfg(test)]
mod tests {
    use super::{ALL_ACTIONS, ActionCatalog, ActorKind, CatalogError, Process, SpecAction};

    fn spec_source() -> String {
        std::fs::read_to_string(crate::spec_path(crate::production_identity::FAMILY.module))
            .expect("ProductionIdentityCser.tla is readable")
    }

    #[test]
    fn derives_every_event_with_its_process_and_actor() {
        let catalog = ActionCatalog::from_spec_source(&spec_source()).expect("catalog builds");
        for action in ALL_ACTIONS {
            assert!(catalog.facts(action).is_some(), "{action} is unresolved");
        }
        let derive = catalog.facts(SpecAction::Derive).expect("Derive resolves");
        assert_eq!(derive.process, Process::Environment);
        assert_eq!(derive.actor, ActorKind::Service);

        // `Crash` lives in the Environment process but is a Kernel-actor
        // event, so process and actor really are independent facts.
        let crash = catalog.facts(SpecAction::Crash).expect("Crash resolves");
        assert_eq!(crash.process, Process::Environment);
        assert_eq!(crash.actor, ActorKind::Kernel);

        let closure = catalog
            .facts(SpecAction::RevokeComplete)
            .expect("RevokeComplete resolves");
        assert_eq!(closure.process, Process::Kernel);
        assert_eq!(closure.actor, ActorKind::Kernel);
    }

    #[test]
    fn rejects_an_event_reordered_in_the_translation_only() {
        let source = spec_source();
        let mutated = source.replacen("lastEvent' = \"Snapshot\"", "lastEvent' = \"Ready\"", 1);
        assert!(matches!(
            ActionCatalog::from_spec_source(&mutated),
            Err(CatalogError::OrderingMismatch { .. })
        ));
    }

    #[test]
    fn rejects_an_event_reclassified_against_its_declared_set() {
        let source = spec_source();
        // Move `Adopt` from the declared Service set into the Kernel set
        // without touching the algorithm's `lastActorKind` assignment.
        let mutated = source
            .replacen("\"Adopt\", \"DeviceCommit\"", "\"DeviceCommit\"", 1)
            .replacen(
                "KernelEvents == {\"Crash\"",
                "KernelEvents == {\"Adopt\", \"Crash\"",
                1,
            );
        assert!(matches!(
            ActionCatalog::from_spec_source(&mutated),
            Err(CatalogError::ActorClassMismatch { .. })
        ));
    }

    #[test]
    fn rejects_an_unmodelled_event() {
        let source = spec_source();
        let mutated = source.replace("\"RevokeComplete\"", "\"RevokeFinished\"");
        assert!(matches!(
            ActionCatalog::from_spec_source(&mutated),
            Err(CatalogError::UnknownEvent { .. })
        ));
    }
}
