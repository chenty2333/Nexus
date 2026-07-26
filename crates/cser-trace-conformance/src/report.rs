//! Replay accounting shared by every specification family.
//!
//! Families have their own action vocabularies, so the report keys operations
//! by their specification name rather than by a family-specific enum. That
//! keeps coverage assertions and console output uniform across families.

use std::collections::BTreeMap;

/// Outcome of a successful replay.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReplayReport {
    transitions: usize,
    actions: BTreeMap<&'static str, usize>,
}

impl ReplayReport {
    /// Records one replayed transition performed by `action`.
    pub fn record(&mut self, action: &'static str) {
        self.transitions += 1;
        *self.actions.entry(action).or_insert(0) += 1;
    }

    /// Returns the number of replayed transitions.
    #[must_use]
    pub const fn transitions(&self) -> usize {
        self.transitions
    }

    /// Returns how often each operation was replayed, keyed by its
    /// specification name.
    #[must_use]
    pub const fn actions(&self) -> &BTreeMap<&'static str, usize> {
        &self.actions
    }

    /// Folds `other` into this report.
    pub fn merge(&mut self, other: &Self) {
        self.transitions += other.transitions;
        for (action, count) in &other.actions {
            *self.actions.entry(action).or_insert(0) += count;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReplayReport;

    #[test]
    fn accumulates_and_merges() {
        let mut left = ReplayReport::default();
        left.record("commit");
        left.record("commit");
        let mut right = ReplayReport::default();
        right.record("adopt");

        left.merge(&right);
        assert_eq!(left.transitions(), 3);
        assert_eq!(left.actions().get("commit"), Some(&2));
        assert_eq!(left.actions().get("adopt"), Some(&1));
    }
}
