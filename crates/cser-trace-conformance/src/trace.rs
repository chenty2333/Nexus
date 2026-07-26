//! Parser for the behavior traces TLC prints with an invariant violation.
//!
//! TLC renders a counterexample as a numbered sequence of states, each headed
//! by the action that produced it and followed by one `/\ var = value`
//! conjunct per specification variable. Long values are wrapped onto
//! continuation lines that this parser rejoins before handing the text to
//! [`crate::value`].

use core::fmt;
use std::collections::BTreeMap;

use crate::value::{self, TlaValue, ValueError};

/// The action TLC attributes to a trace state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionLabel {
    /// The behavior's initial state, produced by `Init`.
    Initial,
    /// A state produced by a named top-level definition.
    ///
    /// `Next == Environment \/ FallbackPick` makes every environment branch
    /// report the same definition name, so the disjunct's source line is the
    /// only thing that distinguishes one protocol operation from another.
    Definition {
        /// Definition name, `Environment` or `FallbackPick` for `Cser.tla`.
        name: String,
        /// One-based source line where the applied disjunct starts.
        start_line: u32,
    },
}

/// One state of a TLC counterexample.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceState {
    /// One-based position in the behavior, as printed by TLC.
    pub index: u32,
    /// Action that produced this state.
    pub action: ActionLabel,
    /// Variable assignment, keyed by specification variable name.
    pub variables: BTreeMap<String, TlaValue>,
}

impl TraceState {
    /// Returns the value bound to `variable`.
    #[must_use]
    pub fn get(&self, variable: &str) -> Option<&TlaValue> {
        self.variables.get(variable)
    }
}

/// A complete TLC counterexample behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trace {
    /// Invariant whose violation produced this behavior.
    pub invariant: String,
    /// States in behavior order, starting with the initial state.
    pub states: Vec<TraceState>,
}

impl Trace {
    /// Returns the number of transitions, which is one fewer than the number
    /// of states.
    #[must_use]
    pub fn transitions(&self) -> usize {
        self.states.len().saturating_sub(1)
    }
}

/// Rejected TLC output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceError {
    /// The run reported no invariant violation, so there is no behavior.
    NoViolation,
    /// The violation report contained no state block.
    NoStates,
    /// A `State N:` header was not followed by a recognizable action label.
    MalformedHeader {
        /// The offending header line.
        line: String,
    },
    /// TLC printed a lasso or stuttering marker; this lane replays only the
    /// finite safety counterexamples produced by invariant violations.
    UnsupportedBehavior {
        /// The marker TLC printed.
        marker: String,
    },
    /// State numbering was not the contiguous sequence starting at one.
    NonContiguousStates {
        /// Expected index.
        expected: u32,
        /// Index TLC printed.
        found: u32,
    },
    /// A conjunct line was not of the form `/\ variable = value`.
    MalformedConjunct {
        /// The offending text.
        line: String,
    },
    /// A state bound the same variable twice.
    DuplicateVariable {
        /// Variable name.
        name: String,
    },
    /// A conjunct's right-hand side was not a supported TLA+ value.
    Value {
        /// Variable whose value failed to parse.
        variable: String,
        /// Underlying parse failure.
        source: ValueError,
    },
}

impl fmt::Display for TraceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoViolation => formatter.write_str("TLC output contains no invariant violation"),
            Self::NoStates => formatter.write_str("TLC violation report contains no states"),
            Self::MalformedHeader { line } => write!(formatter, "malformed state header: {line}"),
            Self::UnsupportedBehavior { marker } => {
                write!(formatter, "unsupported behavior marker: {marker}")
            }
            Self::NonContiguousStates { expected, found } => {
                write!(
                    formatter,
                    "expected state {expected} but found state {found}"
                )
            }
            Self::MalformedConjunct { line } => write!(formatter, "malformed conjunct: {line}"),
            Self::DuplicateVariable { name } => {
                write!(formatter, "variable {name} is assigned twice in one state")
            }
            Self::Value { variable, source } => {
                write!(formatter, "variable {variable}: {source}")
            }
        }
    }
}

impl std::error::Error for TraceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Value { source, .. } => Some(source),
            _ => None,
        }
    }
}

const VIOLATION_PREFIX: &str = "Error: Invariant ";
const VIOLATION_SUFFIX: &str = " is violated.";
const STATE_PREFIX: &str = "State ";
const CONJUNCT_PREFIX: &str = "/\\ ";

/// Parses the counterexample behavior out of a complete TLC run log.
///
/// # Errors
///
/// Returns [`TraceError`] when the log reports no violation or when the
/// printed behavior is outside the subset this lane replays.
pub fn parse(log: &str) -> Result<Trace, TraceError> {
    let invariant = log
        .lines()
        .find_map(|line| {
            line.strip_prefix(VIOLATION_PREFIX)
                .and_then(|rest| rest.strip_suffix(VIOLATION_SUFFIX))
        })
        .ok_or(TraceError::NoViolation)?
        .to_owned();

    let mut states: Vec<TraceState> = Vec::new();
    let mut pending: Option<(u32, ActionLabel, Vec<String>)> = None;

    for line in log.lines() {
        if let Some(rest) = line.strip_prefix(STATE_PREFIX) {
            if let Some(state) = pending.take() {
                states.push(finish_state(state)?);
            }
            let (index, label) = parse_header(line, rest)?;
            pending = Some((index, label, Vec::new()));
            continue;
        }
        if pending.is_none() || line.trim().is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix(CONJUNCT_PREFIX) {
            push_conjunct(pending.as_mut(), rest.to_owned());
        } else if line.starts_with(char::is_whitespace) {
            // TLC wraps a long value onto an indented continuation line.
            let continuation = line.trim();
            match pending.as_mut().and_then(|(_, _, held)| held.last_mut()) {
                Some(last) => {
                    last.push(' ');
                    last.push_str(continuation);
                }
                None => {
                    return Err(TraceError::MalformedConjunct {
                        line: line.to_owned(),
                    });
                }
            }
        } else {
            // The trailing summary begins; the behavior is complete.
            let state = pending.take().ok_or(TraceError::NoStates)?;
            states.push(finish_state(state)?);
        }
    }
    if let Some(state) = pending.take() {
        states.push(finish_state(state)?);
    }
    if states.is_empty() {
        return Err(TraceError::NoStates);
    }
    for (position, state) in states.iter().enumerate() {
        let expected = u32::try_from(position)
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        if state.index != expected {
            return Err(TraceError::NonContiguousStates {
                expected,
                found: state.index,
            });
        }
    }
    Ok(Trace { invariant, states })
}

fn push_conjunct(pending: Option<&mut (u32, ActionLabel, Vec<String>)>, conjunct: String) {
    if let Some((_, _, conjuncts)) = pending {
        conjuncts.push(conjunct);
    }
}

fn parse_header(line: &str, rest: &str) -> Result<(u32, ActionLabel), TraceError> {
    let malformed = || TraceError::MalformedHeader {
        line: line.to_owned(),
    };
    let (number, remainder) = rest.split_once(':').ok_or_else(malformed)?;
    let index: u32 = number.trim().parse().map_err(|_| malformed())?;
    let label = remainder
        .trim()
        .strip_prefix('<')
        .and_then(|text| text.strip_suffix('>'))
        .ok_or_else(malformed)?;
    if label == "Initial predicate" {
        return Ok((index, ActionLabel::Initial));
    }
    let mut tokens = label.split_whitespace();
    let name = tokens.next().ok_or_else(malformed)?;
    if tokens.next() != Some("line") {
        return Err(TraceError::UnsupportedBehavior {
            marker: label.to_owned(),
        });
    }
    let start_line: u32 = tokens
        .next()
        .ok_or_else(malformed)?
        .trim_end_matches(',')
        .parse()
        .map_err(|_| malformed())?;
    Ok((
        index,
        ActionLabel::Definition {
            name: name.to_owned(),
            start_line,
        },
    ))
}

fn finish_state(
    (index, action, conjuncts): (u32, ActionLabel, Vec<String>),
) -> Result<TraceState, TraceError> {
    let mut variables = BTreeMap::new();
    for conjunct in conjuncts {
        let (name, text) =
            conjunct
                .split_once('=')
                .ok_or_else(|| TraceError::MalformedConjunct {
                    line: conjunct.clone(),
                })?;
        let name = name.trim().to_owned();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(TraceError::MalformedConjunct {
                line: conjunct.clone(),
            });
        }
        let parsed = value::parse(text.trim()).map_err(|source| TraceError::Value {
            variable: name.clone(),
            source,
        })?;
        if variables.insert(name.clone(), parsed).is_some() {
            return Err(TraceError::DuplicateVariable { name });
        }
    }
    Ok(TraceState {
        index,
        action,
        variables,
    })
}

#[cfg(test)]
mod tests {
    use super::{ActionLabel, TraceError, parse};
    use crate::value::TlaValue;

    const LOG: &str = "\
Error: Invariant CommitAbsent is violated.
Error: The behavior up to this point is:
State 1: <Initial predicate>
/\\ scopeState = \"Active\"
/\\ freeBudget = 2
/\\ effectState = (e0 :> \"Unregistered\" @@ e1 :> \"Unregistered\")

State 2: <Environment line 232, col 19 to line 242, col 224 of module Cser>
/\\ scopeState = \"Active\"
/\\ freeBudget = 1
/\\ effectState = (e0 :> \"Registered\" @@ e1 :> \"Unregistered\")

3 states generated, 3 distinct states found, 0 states left on queue.
";

    #[test]
    fn parses_states_and_action_lines() {
        let trace = parse(LOG).expect("log parses");
        assert_eq!(trace.invariant, "CommitAbsent");
        assert_eq!(trace.states.len(), 2);
        assert_eq!(trace.transitions(), 1);
        assert_eq!(trace.states[0].action, ActionLabel::Initial);
        assert_eq!(
            trace.states[1].action,
            ActionLabel::Definition {
                name: String::from("Environment"),
                start_line: 232,
            }
        );
        assert_eq!(trace.states[1].get("freeBudget"), Some(&TlaValue::Int(1)));
    }

    #[test]
    fn rejects_logs_without_a_violation() {
        assert_eq!(
            parse("Model checking completed. No error has been found."),
            Err(TraceError::NoViolation)
        );
    }

    #[test]
    fn rejoins_wrapped_values() {
        let log = "Error: Invariant X is violated.\nState 1: <Initial predicate>\n/\\ s = (e0 :> 1\n   @@ e1 :> 2)\n";
        let trace = parse(log).expect("wrapped log parses");
        assert_eq!(
            trace.states[0]
                .get("s")
                .and_then(|value| value.apply(&TlaValue::Model(String::from("e1")))),
            Some(&TlaValue::Int(2))
        );
    }
}
