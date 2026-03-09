use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::model::RunObservation;
use crate::seed::ConcurrentSeed;

/// One retained interesting seed plus its observation summary.
#[derive(Clone, Debug)]
pub struct RetainedSeed {
    /// Stable id inside the corpus directory.
    pub id: usize,
    /// Saved seed.
    pub seed: ConcurrentSeed,
    /// Observation from the run that retained it.
    pub observation: RunObservation,
    /// JSON path on disk.
    pub path: PathBuf,
    /// Predictor score at retention time.
    pub predicted_score: f64,
}

/// In-memory corpus triage by semantic edge coverage, state signature, and failure kind.
#[derive(Debug, Default)]
pub struct Corpus {
    seen_edges: BTreeSet<String>,
    seen_states: BTreeSet<u64>,
    seen_failures: BTreeSet<String>,
    edge_counts: BTreeMap<String, u32>,
    state_counts: BTreeMap<u64, u32>,
    failure_counts: BTreeMap<String, u32>,
    retained: Vec<RetainedSeed>,
}

impl Corpus {
    /// Create an empty corpus.
    pub fn new() -> Self {
        Self::default()
    }

    /// Retain the seed when it expands semantic coverage, state coverage, or failures.
    pub fn consider(
        &mut self,
        dir: &Path,
        seed: ConcurrentSeed,
        observation: RunObservation,
    ) -> Result<bool> {
        let predicted_score = self.score_observation(&observation, &seed);
        let new_edge = observation
            .edge_hits
            .iter()
            .any(|edge| self.seen_edges.insert(edge.clone()));
        let new_state = observation
            .state_signatures
            .iter()
            .any(|sig| self.seen_states.insert(*sig));
        let new_failure = observation
            .failure_kind
            .as_ref()
            .is_some_and(|kind| self.seen_failures.insert(kind.clone()));
        if !(new_edge || new_state || new_failure) {
            return Ok(false);
        }

        for edge in &observation.edge_hits {
            *self.edge_counts.entry(edge.clone()).or_default() += 1;
        }
        for state in &observation.state_signatures {
            *self.state_counts.entry(*state).or_default() += 1;
        }
        if let Some(kind) = observation.failure_kind.as_ref() {
            *self.failure_counts.entry(kind.clone()).or_default() += 1;
        }

        fs::create_dir_all(dir)?;
        let id = self.retained.len();
        let path = dir.join(format!("seed-{id:04}.json"));
        fs::write(&path, serde_json::to_vec_pretty(&seed)?)?;
        self.retained.push(RetainedSeed {
            id,
            seed,
            observation,
            path,
            predicted_score,
        });
        Ok(true)
    }

    /// Retained seeds in insertion order.
    pub fn retained(&self) -> &[RetainedSeed] {
        &self.retained
    }

    /// Pick one retained parent according to the current predictor.
    pub fn pick_parent(&self, round: usize) -> Option<&RetainedSeed> {
        if self.retained.is_empty() {
            return None;
        }
        let mut ranked = self.retained.iter().collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            right
                .predicted_score
                .total_cmp(&left.predicted_score)
                .then_with(|| left.id.cmp(&right.id))
        });
        let top = ranked.len().min(4);
        Some(ranked[round % top])
    }

    fn score_observation(&self, observation: &RunObservation, seed: &ConcurrentSeed) -> f64 {
        let edge_score = observation.edge_hits.iter().fold(0.0, |acc, edge| {
            let seen = self.edge_counts.get(edge).copied().unwrap_or(0);
            acc + 1.0 / f64::from(seen + 1)
        });
        let state_score = observation.state_signatures.iter().fold(0.0, |acc, state| {
            let seen = self.state_counts.get(state).copied().unwrap_or(0);
            acc + 0.5 / f64::from(seen + 1)
        });
        let failure_score = observation.failure_kind.as_ref().map_or(0.0, |kind| {
            let seen = self.failure_counts.get(kind).copied().unwrap_or(0);
            4.0 / f64::from(seen + 1)
        });
        let hint_score = (seed.hints.len().min(4) as f64) * 0.1;
        let op_score = ((seed.program_a.len() + seed.program_b.len()).min(12) as f64) * 0.05;
        edge_score + state_score + failure_score + hint_score + op_score
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::seed::ConcurrentSeed;

    #[test]
    fn corpus_keeps_new_state_signature_even_without_new_edges() {
        let temp = tempdir().unwrap();
        let mut corpus = Corpus::new();
        let seed = ConcurrentSeed::base_corpus(32).remove(0);
        let mut obs = RunObservation::default();
        obs.edge_hits.insert("edge:a".into());
        obs.state_signatures.insert(1);
        assert!(
            corpus
                .consider(temp.path(), seed.clone(), obs.clone())
                .unwrap()
        );

        let mut obs2 = RunObservation::default();
        obs2.edge_hits.insert("edge:a".into());
        obs2.state_signatures.insert(2);
        assert!(corpus.consider(temp.path(), seed, obs2).unwrap());
        assert_eq!(corpus.retained().len(), 2);
    }

    #[test]
    fn predictor_prefers_rare_observations() {
        let temp = tempdir().unwrap();
        let mut corpus = Corpus::new();
        let seed = ConcurrentSeed::base_corpus(32).remove(0);
        let mut common = RunObservation::default();
        common.edge_hits.insert("edge:common".into());
        common.state_signatures.insert(1);
        assert!(
            corpus
                .consider(temp.path(), seed.clone(), common.clone())
                .unwrap()
        );

        let mut rare = RunObservation::default();
        rare.edge_hits.insert("edge:rare".into());
        rare.state_signatures.insert(2);
        assert!(corpus.consider(temp.path(), seed, rare).unwrap());

        let parent = corpus.pick_parent(0).unwrap();
        assert!(parent.predicted_score >= corpus.retained()[0].predicted_score);
    }
}
