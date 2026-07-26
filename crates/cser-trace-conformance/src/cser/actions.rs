//! Resolution of TLC action labels to `Cser.tla` protocol operations.
//!
//! The PlusCal algorithm puts all eleven operations in two processes, so the
//! generated `Next` relation exposes exactly two definition names. TLC's trace
//! header therefore identifies an operation only by the source line at which
//! the applied disjunct starts.
//!
//! Rather than hard-coding those line numbers, the catalog reads `Cser.tla`
//! and derives them, cross-checking two independent orderings that must agree:
//! the `\* name(...)` comments on the `either`/`or` branches of the PlusCal
//! source, and the top-level disjuncts of the checked-in translation. If the
//! spec gains, loses, or reorders a branch, catalog construction fails instead
//! of silently mapping traces onto the wrong operations.

use core::fmt;
use std::collections::BTreeMap;

use crate::trace::ActionLabel;

/// One atomic protocol operation of `Cser.tla`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SpecAction {
    /// `register(e)`: reserve a credit and bind an effect to the live scope.
    Register,
    /// `prepare(e)`: finish construction without any visible effect.
    Prepare,
    /// `commit(e)`: the effect commit linearization point.
    Commit,
    /// `complete(e)`: normal completion after an irreversible commit.
    Complete,
    /// `revoke_begin()`: the revocation linearization point.
    RevokeBegin,
    /// `revoke_step(e)`: one unit of cancellation or drainage work.
    RevokeStep,
    /// `revoke_complete()`: quiescent closure acknowledgement.
    RevokeComplete,
    /// `crash()`: fence a failed supervisor and request kernel fallback.
    Crash,
    /// `rebind()`: install a replacement supervisor.
    Rebind,
    /// `adopt(e)`: move an uncommitted effect to the current binding.
    Adopt,
    /// The kernel-owned scheduler fallback process step.
    FallbackPick,
}

impl SpecAction {
    /// Returns the operation's `Cser.tla` name.
    #[must_use]
    pub const fn spec_name(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Prepare => "prepare",
            Self::Commit => "commit",
            Self::Complete => "complete",
            Self::RevokeBegin => "revoke_begin",
            Self::RevokeStep => "revoke_step",
            Self::RevokeComplete => "revoke_complete",
            Self::Crash => "crash",
            Self::Rebind => "rebind",
            Self::Adopt => "adopt",
            Self::FallbackPick => "FallbackPick",
        }
    }
}

impl fmt::Display for SpecAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.spec_name())
    }
}

/// Every operation this lane knows how to replay, in specification order.
pub const ALL_ACTIONS: [SpecAction; 11] = [
    SpecAction::Register,
    SpecAction::Prepare,
    SpecAction::Commit,
    SpecAction::Complete,
    SpecAction::RevokeBegin,
    SpecAction::RevokeStep,
    SpecAction::RevokeComplete,
    SpecAction::Crash,
    SpecAction::Rebind,
    SpecAction::Adopt,
    SpecAction::FallbackPick,
];

/// The `Environment` branches in the order both the PlusCal source and its
/// translation must present them.
const ENVIRONMENT_BRANCHES: [SpecAction; 10] = [
    SpecAction::Register,
    SpecAction::Prepare,
    SpecAction::Commit,
    SpecAction::Complete,
    SpecAction::RevokeBegin,
    SpecAction::RevokeStep,
    SpecAction::RevokeComplete,
    SpecAction::Crash,
    SpecAction::Rebind,
    SpecAction::Adopt,
];

const ENVIRONMENT_DEFINITION: &str = "Environment ==";
const FALLBACK_DEFINITION: &str = "FallbackPick ==";
const ALGORITHM_LOOP: &str = "EnvironmentLoop:";
const ALGORITHM_PROCESS_END: &str = "end process;";

/// Rejected specification source or trace label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogError {
    /// A required definition or PlusCal marker was absent.
    MissingAnchor {
        /// Text the catalog searched for.
        anchor: &'static str,
    },
    /// The PlusCal branch comments did not match the pinned operation list.
    BranchNames {
        /// Names found in the algorithm block, in order.
        found: Vec<String>,
    },
    /// The translated `Environment` definition had an unexpected disjunct
    /// count.
    BranchCount {
        /// Number of top-level disjuncts found.
        found: usize,
    },
    /// A trace referenced a definition the catalog does not model.
    UnknownDefinition {
        /// Definition name printed by TLC.
        name: String,
    },
    /// A trace referenced a source line that starts no known disjunct.
    UnknownDisjunct {
        /// Definition name printed by TLC.
        name: String,
        /// Source line printed by TLC.
        start_line: u32,
    },
    /// The trace's initial state was used where a transition was required.
    InitialState,
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAnchor { anchor } => {
                write!(formatter, "Cser.tla does not contain {anchor:?}")
            }
            Self::BranchNames { found } => write!(
                formatter,
                "PlusCal branch comments {found:?} do not match the pinned operation order"
            ),
            Self::BranchCount { found } => write!(
                formatter,
                "translated Environment has {found} top-level disjuncts; expected {}",
                ENVIRONMENT_BRANCHES.len()
            ),
            Self::UnknownDefinition { name } => {
                write!(formatter, "trace names unmodelled definition {name}")
            }
            Self::UnknownDisjunct { name, start_line } => write!(
                formatter,
                "trace names {name} line {start_line}, which starts no known disjunct"
            ),
            Self::InitialState => {
                formatter.write_str("the initial state has no protocol operation")
            }
        }
    }
}

impl std::error::Error for CatalogError {}

/// Mapping from TLC action labels to protocol operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionCatalog {
    environment: BTreeMap<u32, SpecAction>,
    fallback_line: u32,
}

impl ActionCatalog {
    /// Derives the catalog from the text of `specs/cser/Cser.tla`.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] when the specification's operation set or
    /// order no longer matches what this lane replays.
    pub fn from_spec_source(source: &str) -> Result<Self, CatalogError> {
        let lines: Vec<&str> = source.lines().collect();
        Self::check_algorithm_branch_names(&lines)?;

        let definition = lines
            .iter()
            .position(|line| line.starts_with(ENVIRONMENT_DEFINITION))
            .ok_or(CatalogError::MissingAnchor {
                anchor: ENVIRONMENT_DEFINITION,
            })?;
        let indent = lines[definition]
            .find("\\/")
            .ok_or(CatalogError::MissingAnchor {
                anchor: ENVIRONMENT_DEFINITION,
            })?;

        let mut starts = vec![definition];
        for (offset, line) in lines.iter().enumerate().skip(definition + 1) {
            if line.trim().is_empty() || !line.is_char_boundary(indent) {
                break;
            }
            let (prefix, rest) = line.split_at(indent);
            if !prefix.chars().all(char::is_whitespace) {
                break;
            }
            if rest.starts_with("\\/") {
                starts.push(offset);
            }
        }
        if starts.len() != ENVIRONMENT_BRANCHES.len() {
            return Err(CatalogError::BranchCount {
                found: starts.len(),
            });
        }

        let environment = starts
            .into_iter()
            .zip(ENVIRONMENT_BRANCHES)
            .map(|(offset, action)| (one_based_line(offset), action))
            .collect();

        let fallback = lines
            .iter()
            .position(|line| line.starts_with(FALLBACK_DEFINITION))
            .ok_or(CatalogError::MissingAnchor {
                anchor: FALLBACK_DEFINITION,
            })?;

        Ok(Self {
            environment,
            fallback_line: one_based_line(fallback),
        })
    }

    /// Resolves the operation that produced a trace state.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for the initial state, for definitions outside
    /// `Next`, and for source lines that start no known disjunct.
    pub fn resolve(&self, label: &ActionLabel) -> Result<SpecAction, CatalogError> {
        let ActionLabel::Definition { name, start_line } = label else {
            return Err(CatalogError::InitialState);
        };
        match name.as_str() {
            "Environment" => self.environment.get(start_line).copied().ok_or_else(|| {
                CatalogError::UnknownDisjunct {
                    name: name.clone(),
                    start_line: *start_line,
                }
            }),
            "FallbackPick" if *start_line == self.fallback_line => Ok(SpecAction::FallbackPick),
            "FallbackPick" => Err(CatalogError::UnknownDisjunct {
                name: name.clone(),
                start_line: *start_line,
            }),
            _ => Err(CatalogError::UnknownDefinition { name: name.clone() }),
        }
    }

    fn check_algorithm_branch_names(lines: &[&str]) -> Result<(), CatalogError> {
        let start = lines
            .iter()
            .position(|line| line.trim() == ALGORITHM_LOOP)
            .ok_or(CatalogError::MissingAnchor {
                anchor: ALGORITHM_LOOP,
            })?;
        let end = lines
            .iter()
            .skip(start)
            .position(|line| line.trim() == ALGORITHM_PROCESS_END)
            .ok_or(CatalogError::MissingAnchor {
                anchor: ALGORITHM_PROCESS_END,
            })?
            + start;

        let found: Vec<String> = lines[start..end]
            .iter()
            .filter_map(|line| branch_comment_name(line))
            .collect();
        let expected: Vec<&str> = ENVIRONMENT_BRANCHES
            .iter()
            .map(|action| action.spec_name())
            .collect();
        if found != expected {
            return Err(CatalogError::BranchNames { found });
        }
        Ok(())
    }
}

/// Extracts `name` from a PlusCal branch comment of the form `\* name(...)`.
fn branch_comment_name(line: &str) -> Option<String> {
    let comment = line.trim_start().strip_prefix("\\* ")?;
    let name: String = comment
        .chars()
        .take_while(|c| c.is_ascii_lowercase() || *c == '_')
        .collect();
    if name.is_empty() || !comment[name.len()..].starts_with('(') {
        return None;
    }
    Some(name)
}

fn one_based_line(offset: usize) -> u32 {
    u32::try_from(offset).unwrap_or(u32::MAX).saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::{ActionCatalog, CatalogError, SpecAction, branch_comment_name};
    use crate::trace::ActionLabel;

    fn spec_source() -> String {
        std::fs::read_to_string(crate::spec_path(crate::cser::FAMILY.module))
            .expect("Cser.tla is readable")
    }

    #[test]
    fn derives_every_environment_branch() {
        let catalog = ActionCatalog::from_spec_source(&spec_source()).expect("catalog builds");
        let mut resolved: Vec<SpecAction> = catalog.environment.values().copied().collect();
        resolved.sort_unstable();
        assert_eq!(resolved.len(), 10);
        assert!(resolved.windows(2).all(|pair| pair[0] != pair[1]));
    }

    #[test]
    fn rejects_a_reordered_algorithm() {
        let mutated = spec_source().replace("\\* prepare(e):", "\\* commit(e):");
        assert!(matches!(
            ActionCatalog::from_spec_source(&mutated),
            Err(CatalogError::BranchNames { .. })
        ));
    }

    #[test]
    fn rejects_unknown_labels() {
        let catalog = ActionCatalog::from_spec_source(&spec_source()).expect("catalog builds");
        assert!(matches!(
            catalog.resolve(&ActionLabel::Initial),
            Err(CatalogError::InitialState)
        ));
        assert!(matches!(
            catalog.resolve(&ActionLabel::Definition {
                name: String::from("Environment"),
                start_line: 1,
            }),
            Err(CatalogError::UnknownDisjunct { .. })
        ));
        assert!(matches!(
            catalog.resolve(&ActionLabel::Definition {
                name: String::from("Spec"),
                start_line: 1,
            }),
            Err(CatalogError::UnknownDefinition { .. })
        ));
    }

    #[test]
    fn reads_only_operation_comments() {
        assert_eq!(
            branch_comment_name("            \\* revoke_step(e): bounded work"),
            Some(String::from("revoke_step"))
        );
        assert_eq!(
            branch_comment_name("            \\* index.  Uncommitted"),
            None
        );
        assert_eq!(branch_comment_name("        either"), None);
    }
}
