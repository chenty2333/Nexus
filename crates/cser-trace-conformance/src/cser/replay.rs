//! Replay of a TLC behavior against the `cser-model` reference oracle.
//!
//! # What one replayed step checks
//!
//! For each transition of the behavior the replayer takes three inputs from
//! different places, so that agreement is evidence rather than restatement:
//!
//! * the **operation** comes from TLC's action label, resolved through
//!   [`crate::actions::ActionCatalog`];
//! * the **operand** (which effect) comes from the trace's state delta;
//! * the **resulting state** is computed independently by `cser-model` and is
//!   then required to project onto TLC's rendering of the successor state.
//!
//! The oracle never sees the spec's successor state before producing its own,
//! so a disagreement in any projected variable fails the step.
//!
//! # Abstraction mismatches
//!
//! * **Epoch origin.** `Cser.tla` numbers the first authority and binding
//!   epoch `0`; `cser-model` numbers it `1`. The projection subtracts one.
//! * **Effect identity.** The spec fixes a finite CONSTANT set of effect model
//!   values; the oracle allocates [`EffectId`]s at registration. The replayer
//!   maintains the bijection built at each `register` step, and an effect the
//!   spec has not registered has no oracle record at all.
//! * **Supervisor identity.** `supervisorAlive` is a boolean; the oracle
//!   installs a distinct [`SupervisorId`] per binding. The projection keeps
//!   only "a supervisor is installed".
//! * **Fallback encoding.** `fallbackState` is a three-valued string; the
//!   oracle uses `fallback_pending`/`fallback_selected`. The projection maps
//!   the pair back, relying on the oracle's own invariant that exactly one of
//!   the two holds while no supervisor is installed.
//! * **Revocation schedule.** `revoke_step(e)` lets the spec pick any live
//!   effect; the oracle's `revoke_step` deterministically advances the least
//!   live effect. When a trace picks a different effect the replayer reports
//!   [`ConformanceError::RevokeSelectionDivergence`] instead of weakening the
//!   comparison. Such a trace is outside this lane, not evidence of a defect.
//! * **History variables.** `commitBinding`, `committedAtClose`,
//!   `committedAtLastCrash`, and `lastCrashBinding` exist only to state
//!   `Cser.tla`'s invariants and have no oracle counterpart, so they are not
//!   projected. The other fourteen variables are.

use core::fmt;
use std::collections::BTreeMap;

use cser_model::{
    BindingToken, Budget, BudgetDisposition, EffectId, EffectState, InvariantViolation, Model,
    ModelError, ScopeId, ScopeState, SupervisorId,
};

use crate::cser::actions::{ActionCatalog, CatalogError, SpecAction};
use crate::report::ReplayReport;
use crate::trace::{Trace, TraceState};
use crate::value::TlaValue;

/// Specification variables the oracle reproduces and the replayer compares.
pub const PROJECTED_VARIABLES: [&str; 14] = [
    "bindingEpoch",
    "closingEpoch",
    "commitSeen",
    "effectBinding",
    "effectEpoch",
    "effectState",
    "fallbackState",
    "freeBudget",
    "held",
    "scopeEpoch",
    "scopeState",
    "spent",
    "supervisorAlive",
    "terminalCount",
];

/// Specification variables with no oracle counterpart.
///
/// These are history variables that `Cser.tla` maintains solely to phrase
/// `PostRevokeCommitExclusion` and `OldBindingCannotCommit`. This lane
/// establishes nothing about them.
pub const UNPROJECTED_VARIABLES: [&str; 4] = [
    "commitBinding",
    "committedAtClose",
    "committedAtLastCrash",
    "lastCrashBinding",
];

/// Why a behavior was rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConformanceError {
    /// The action label could not be resolved to an operation.
    Catalog(CatalogError),
    /// The oracle rejected an operation the specification took.
    Rejected {
        /// State the operation was meant to produce.
        state_index: u32,
        /// Operation resolved from the action label.
        action: SpecAction,
        /// Oracle rejection.
        source: ModelError,
    },
    /// The oracle's own invariant audit failed after an accepted operation.
    Invariant {
        /// State the operation produced.
        state_index: u32,
        /// Audit failure.
        source: InvariantViolation,
    },
    /// A projected variable disagreed with the specification's state.
    ProjectionMismatch {
        /// State in which the disagreement appeared.
        state_index: u32,
        /// Projected variable name.
        variable: &'static str,
        /// Value TLC printed.
        expected: TlaValue,
        /// Value the oracle produced.
        actual: TlaValue,
    },
    /// A state omitted a variable the projection needs.
    MissingVariable {
        /// State index.
        state_index: u32,
        /// Variable name.
        variable: &'static str,
    },
    /// A variable that must be a function over the effect set was not one.
    MalformedVariable {
        /// State index.
        state_index: u32,
        /// Variable name.
        variable: &'static str,
    },
    /// The state delta did not identify exactly one operand effect.
    Operand {
        /// State index.
        state_index: u32,
        /// Operation whose operand was being derived.
        action: SpecAction,
        /// Variable inspected for the delta.
        variable: &'static str,
        /// Number of effects whose entry changed.
        changed: usize,
    },
    /// An operation named an effect the specification never registered.
    UnregisteredEffect {
        /// State index.
        state_index: u32,
        /// Effect model value.
        effect: TlaValue,
    },
    /// An operation requiring a live supervisor found none installed.
    NoCurrentBinding {
        /// State index.
        state_index: u32,
        /// Operation that needed the binding.
        action: SpecAction,
    },
    /// The specification took a revocation step the oracle had no work for.
    RevokeStepUnavailable {
        /// State index.
        state_index: u32,
    },
    /// The oracle's deterministic revocation schedule chose another effect.
    RevokeSelectionDivergence {
        /// State index.
        state_index: u32,
        /// Effect the specification advanced.
        specification: TlaValue,
        /// Effect the oracle advanced.
        oracle: EffectId,
    },
    /// A `register` step produced an effect identity that was already bound.
    DuplicateRegistration {
        /// State index.
        state_index: u32,
        /// Effect model value.
        effect: TlaValue,
    },
    /// The initial state did not describe a startable scope.
    MalformedInitialState {
        /// What the replayer required.
        detail: &'static str,
    },
    /// The oracle state could not be rendered in the specification's
    /// vocabulary.
    Unprojectable {
        /// What went wrong.
        detail: &'static str,
    },
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(source) => write!(formatter, "{source}"),
            Self::Rejected {
                state_index,
                action,
                source,
            } => write!(
                formatter,
                "state {state_index}: oracle rejected {action}: {source:?}"
            ),
            Self::Invariant {
                state_index,
                source,
            } => write!(
                formatter,
                "state {state_index}: oracle audit failed: {source:?}"
            ),
            Self::ProjectionMismatch {
                state_index,
                variable,
                expected,
                actual,
            } => write!(
                formatter,
                "state {state_index}: {variable} is {expected} in the specification \
                 but {actual} in the oracle"
            ),
            Self::MissingVariable {
                state_index,
                variable,
            } => write!(formatter, "state {state_index}: {variable} is missing"),
            Self::MalformedVariable {
                state_index,
                variable,
            } => write!(
                formatter,
                "state {state_index}: {variable} is not a function over the effect set"
            ),
            Self::Operand {
                state_index,
                action,
                variable,
                changed,
            } => write!(
                formatter,
                "state {state_index}: {action} changed {variable} for {changed} effects; \
                 expected exactly one"
            ),
            Self::UnregisteredEffect {
                state_index,
                effect,
            } => write!(
                formatter,
                "state {state_index}: effect {effect} is unregistered"
            ),
            Self::NoCurrentBinding {
                state_index,
                action,
            } => write!(
                formatter,
                "state {state_index}: {action} requires a live supervisor binding"
            ),
            Self::RevokeStepUnavailable { state_index } => write!(
                formatter,
                "state {state_index}: the oracle had no revocation work left"
            ),
            Self::RevokeSelectionDivergence {
                state_index,
                specification,
                oracle,
            } => write!(
                formatter,
                "state {state_index}: the specification advanced {specification} but the \
                 oracle schedule advanced effect {}",
                oracle.get()
            ),
            Self::DuplicateRegistration {
                state_index,
                effect,
            } => write!(
                formatter,
                "state {state_index}: effect {effect} was registered twice"
            ),
            Self::MalformedInitialState { detail } => {
                write!(formatter, "initial state is unusable: {detail}")
            }
            Self::Unprojectable { detail } => {
                write!(formatter, "oracle state is unprojectable: {detail}")
            }
        }
    }
}

impl std::error::Error for ConformanceError {}

impl From<CatalogError> for ConformanceError {
    fn from(source: CatalogError) -> Self {
        Self::Catalog(source)
    }
}

/// Replays a complete behavior against a fresh oracle instance.
///
/// # Errors
///
/// Returns [`ConformanceError`] as soon as any step fails to resolve, is
/// rejected by the oracle, or produces a state that does not project onto the
/// specification's state.
pub fn replay(trace: &Trace, catalog: &ActionCatalog) -> Result<ReplayReport, ConformanceError> {
    let initial = trace
        .states
        .first()
        .ok_or(ConformanceError::MalformedInitialState {
            detail: "the behavior has no states",
        })?;
    let mut replayer = Replayer::start(initial)?;
    let mut report = ReplayReport::default();

    for pair in trace.states.windows(2) {
        let (previous, current) = (&pair[0], &pair[1]);
        let action = catalog.resolve(&current.action)?;
        replayer.apply(action, previous, current)?;
        report.record(action.spec_name());
    }

    Ok(report)
}

/// Oracle-side replay state for one behavior.
#[derive(Debug)]
struct Replayer {
    model: Model,
    scope: ScopeId,
    effect_names: Vec<TlaValue>,
    effects: BTreeMap<TlaValue, EffectId>,
    supervisors: u64,
}

impl Replayer {
    fn start(initial: &TraceState) -> Result<Self, ConformanceError> {
        let effect_names: Vec<TlaValue> = initial
            .get("effectState")
            .and_then(TlaValue::domain)
            .ok_or(ConformanceError::MalformedInitialState {
                detail: "effectState is not a function over the effect set",
            })?
            .into_iter()
            .cloned()
            .collect();
        let budget = initial
            .get("freeBudget")
            .and_then(TlaValue::as_int)
            .and_then(|units| u64::try_from(units).ok())
            .ok_or(ConformanceError::MalformedInitialState {
                detail: "freeBudget is not a nonnegative integer",
            })?;

        let mut model = Model::new();
        let supervisors = 1;
        let (scope, _binding) = model
            .create_scope(SupervisorId::new(supervisors), Budget::new(budget))
            .map_err(|_| ConformanceError::MalformedInitialState {
                detail: "the oracle could not create the initial scope",
            })?;
        let replayer = Self {
            model,
            scope,
            effect_names,
            effects: BTreeMap::new(),
            supervisors,
        };
        replayer.compare(initial)?;
        Ok(replayer)
    }

    fn apply(
        &mut self,
        action: SpecAction,
        previous: &TraceState,
        current: &TraceState,
    ) -> Result<(), ConformanceError> {
        let index = current.index;
        match action {
            SpecAction::Register => {
                let name = self.operand(action, "effectState", previous, current)?;
                if self.effects.contains_key(&name) {
                    return Err(ConformanceError::DuplicateRegistration {
                        state_index: index,
                        effect: name,
                    });
                }
                let binding = self.binding(action, index)?;
                // Each spec effect carries exactly one credit: `held` and
                // `spent` are both booleans in `Cser.tla`.
                let effect = self
                    .model
                    .register(binding, Budget::new(1))
                    .map_err(|source| rejected(index, action, source))?;
                self.effects.insert(name, effect);
            }
            SpecAction::Prepare => {
                let effect = self.operand_effect(action, "effectState", previous, current)?;
                let binding = self.binding(action, index)?;
                self.model
                    .prepare(binding, effect)
                    .map_err(|source| rejected(index, action, source))?;
            }
            SpecAction::Commit => {
                let effect = self.operand_effect(action, "effectState", previous, current)?;
                let binding = self.binding(action, index)?;
                self.model
                    .commit(binding, effect)
                    .map_err(|source| rejected(index, action, source))?;
            }
            SpecAction::Complete => {
                let effect = self.operand_effect(action, "effectState", previous, current)?;
                self.model
                    .complete(effect)
                    .map_err(|source| rejected(index, action, source))?;
            }
            SpecAction::RevokeBegin => {
                self.model
                    .revoke_begin(self.scope)
                    .map_err(|source| rejected(index, action, source))?;
            }
            SpecAction::RevokeStep => {
                let name = self.operand(action, "effectState", previous, current)?;
                let expected = self.effect_id(index, &name)?;
                let step = self
                    .model
                    .revoke_step(self.scope)
                    .map_err(|source| rejected(index, action, source))?
                    .ok_or(ConformanceError::RevokeStepUnavailable { state_index: index })?;
                if step.effect != expected {
                    return Err(ConformanceError::RevokeSelectionDivergence {
                        state_index: index,
                        specification: name,
                        oracle: step.effect,
                    });
                }
            }
            SpecAction::RevokeComplete => {
                self.model
                    .revoke_complete(self.scope)
                    .map_err(|source| rejected(index, action, source))?;
            }
            SpecAction::Crash => {
                let binding = self.binding(action, index)?;
                self.model
                    .crash(binding)
                    .map_err(|source| rejected(index, action, source))?;
            }
            SpecAction::Rebind => {
                self.supervisors = self.supervisors.saturating_add(1);
                self.model
                    .rebind(self.scope, SupervisorId::new(self.supervisors))
                    .map_err(|source| rejected(index, action, source))?;
            }
            SpecAction::Adopt => {
                let effect = self.operand_effect(action, "effectBinding", previous, current)?;
                let binding = self.binding(action, index)?;
                self.model
                    .adopt(binding, effect)
                    .map_err(|source| rejected(index, action, source))?;
            }
            SpecAction::FallbackPick => {
                self.model
                    .fallback_pick(self.scope)
                    .map_err(|source| rejected(index, action, source))?;
            }
        }

        self.model
            .check_invariants()
            .map_err(|source| ConformanceError::Invariant {
                state_index: index,
                source,
            })?;
        self.compare(current)
    }

    fn binding(
        &self,
        action: SpecAction,
        state_index: u32,
    ) -> Result<BindingToken, ConformanceError> {
        self.model
            .current_binding(self.scope)
            .ok_or(ConformanceError::NoCurrentBinding {
                state_index,
                action,
            })
    }

    /// Returns the single effect whose entry in `variable` changed.
    fn operand(
        &self,
        action: SpecAction,
        variable: &'static str,
        previous: &TraceState,
        current: &TraceState,
    ) -> Result<TlaValue, ConformanceError> {
        let before = function_of(previous, variable)?;
        let after = function_of(current, variable)?;
        let mut changed: Vec<&TlaValue> = Vec::new();
        for name in &self.effect_names {
            if before.apply(name) != after.apply(name) {
                changed.push(name);
            }
        }
        match changed.as_slice() {
            [only] => Ok((*only).clone()),
            other => Err(ConformanceError::Operand {
                state_index: current.index,
                action,
                variable,
                changed: other.len(),
            }),
        }
    }

    fn operand_effect(
        &self,
        action: SpecAction,
        variable: &'static str,
        previous: &TraceState,
        current: &TraceState,
    ) -> Result<EffectId, ConformanceError> {
        let name = self.operand(action, variable, previous, current)?;
        self.effect_id(current.index, &name)
    }

    fn effect_id(&self, state_index: u32, name: &TlaValue) -> Result<EffectId, ConformanceError> {
        self.effects
            .get(name)
            .copied()
            .ok_or_else(|| ConformanceError::UnregisteredEffect {
                state_index,
                effect: name.clone(),
            })
    }

    /// Requires every projected variable of the oracle to equal the
    /// specification's rendering of the same variable.
    fn compare(&self, state: &TraceState) -> Result<(), ConformanceError> {
        for (variable, actual) in self.project()? {
            let expected = state
                .get(variable)
                .ok_or(ConformanceError::MissingVariable {
                    state_index: state.index,
                    variable,
                })?;
            if *expected != actual {
                return Err(ConformanceError::ProjectionMismatch {
                    state_index: state.index,
                    variable,
                    expected: expected.clone(),
                    actual,
                });
            }
        }
        Ok(())
    }

    /// Renders the oracle's state in the specification's vocabulary.
    fn project(&self) -> Result<Vec<(&'static str, TlaValue)>, ConformanceError> {
        let scope = self
            .model
            .scope(self.scope)
            .ok_or(ConformanceError::Unprojectable {
                detail: "the replayed scope disappeared",
            })?;

        let mut effect_state = Vec::with_capacity(self.effect_names.len());
        let mut effect_epoch = Vec::with_capacity(self.effect_names.len());
        let mut effect_binding = Vec::with_capacity(self.effect_names.len());
        let mut held = Vec::with_capacity(self.effect_names.len());
        let mut spent = Vec::with_capacity(self.effect_names.len());
        let mut commit_seen = Vec::with_capacity(self.effect_names.len());
        let mut terminal_count = Vec::with_capacity(self.effect_names.len());

        for name in &self.effect_names {
            let view = self
                .effects
                .get(name)
                .and_then(|effect| self.model.effect(*effect));
            let key = name.clone();
            match view {
                Some(view) => {
                    effect_state.push((key.clone(), TlaValue::Str(effect_state_name(view.state))));
                    effect_epoch.push((key.clone(), tla_epoch(view.scope_epoch)?));
                    effect_binding.push((key.clone(), tla_epoch(view.binding_epoch)?));
                    let is_held = view.budget_disposition == BudgetDisposition::Held;
                    let is_spent = view.budget_disposition == BudgetDisposition::Spent;
                    held.push((key.clone(), TlaValue::Int(i64::from(is_held))));
                    spent.push((key.clone(), TlaValue::Int(i64::from(is_spent))));
                    // A committed effect never returns to a held or returned
                    // disposition, so `spent` is exactly `commitSeen`.
                    commit_seen.push((key.clone(), TlaValue::Bool(is_spent)));
                    terminal_count.push((key, TlaValue::Int(i64::from(view.terminalizations))));
                }
                None => {
                    effect_state.push((key.clone(), TlaValue::Str(String::from("Unregistered"))));
                    effect_epoch.push((key.clone(), TlaValue::Int(NO_EPOCH)));
                    effect_binding.push((key.clone(), TlaValue::Int(NO_BINDING)));
                    held.push((key.clone(), TlaValue::Int(0)));
                    spent.push((key.clone(), TlaValue::Int(0)));
                    commit_seen.push((key.clone(), TlaValue::Bool(false)));
                    terminal_count.push((key, TlaValue::Int(0)));
                }
            }
        }

        let closing_epoch = match scope.revocation {
            Some(progress) => tla_epoch(progress.closed_epoch)?,
            None => TlaValue::Int(NO_EPOCH),
        };
        // `check_invariants` guarantees that an unbound scope has exactly one
        // of `fallback_pending` and `fallback_selected` set.
        let fallback = if scope.supervisor.is_some() {
            "Standby"
        } else if scope.fallback_pending {
            "Required"
        } else {
            "Running"
        };

        Ok(vec![
            ("scopeState", TlaValue::Str(scope_state_name(scope.state))),
            ("scopeEpoch", tla_epoch(scope.epoch)?),
            ("closingEpoch", closing_epoch),
            (
                "supervisorAlive",
                TlaValue::Bool(scope.supervisor.is_some()),
            ),
            ("bindingEpoch", tla_epoch(scope.binding_epoch)?),
            ("fallbackState", TlaValue::Str(String::from(fallback))),
            ("effectState", TlaValue::function(effect_state)),
            ("effectEpoch", TlaValue::function(effect_epoch)),
            ("effectBinding", TlaValue::function(effect_binding)),
            (
                "freeBudget",
                TlaValue::Int(i64::try_from(scope.free_budget.units()).map_err(|_| {
                    ConformanceError::Unprojectable {
                        detail: "the oracle's free budget exceeded the integer range",
                    }
                })?),
            ),
            ("held", TlaValue::function(held)),
            ("spent", TlaValue::function(spent)),
            ("commitSeen", TlaValue::function(commit_seen)),
            ("terminalCount", TlaValue::function(terminal_count)),
        ])
    }
}

fn rejected(state_index: u32, action: SpecAction, source: ModelError) -> ConformanceError {
    ConformanceError::Rejected {
        state_index,
        action,
        source,
    }
}

const NO_EPOCH: i64 = -1;
const NO_BINDING: i64 = -1;

/// Converts a one-based oracle epoch to the specification's zero-based epoch.
fn tla_epoch(epoch: u64) -> Result<TlaValue, ConformanceError> {
    let signed = i64::try_from(epoch).map_err(|_| ConformanceError::Unprojectable {
        detail: "an oracle epoch exceeded the specification's integer range",
    })?;
    Ok(TlaValue::Int(signed - 1))
}

fn scope_state_name(state: ScopeState) -> String {
    String::from(match state {
        ScopeState::Active => "Active",
        ScopeState::Closing => "Closing",
        ScopeState::Revoked => "Revoked",
    })
}

fn effect_state_name(state: EffectState) -> String {
    String::from(match state {
        EffectState::Registered => "Registered",
        EffectState::Prepared => "Prepared",
        EffectState::Committed => "Committed",
        EffectState::Draining => "Draining",
        EffectState::Completed => "Completed",
        EffectState::Cancelling => "Cancelling",
        EffectState::Aborted => "Aborted",
    })
}

fn function_of<'a>(
    state: &'a TraceState,
    variable: &'static str,
) -> Result<&'a TlaValue, ConformanceError> {
    let value = state
        .get(variable)
        .ok_or(ConformanceError::MissingVariable {
            state_index: state.index,
            variable,
        })?;
    if matches!(value, TlaValue::Function(_)) {
        Ok(value)
    } else {
        Err(ConformanceError::MalformedVariable {
            state_index: state.index,
            variable,
        })
    }
}
