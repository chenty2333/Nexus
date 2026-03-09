use std::collections::BTreeSet;
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
}

/// In-memory corpus triage by semantic edge coverage, state signature, and failure kind.
#[derive(Debug, Default)]
pub struct Corpus {
    seen_edges: BTreeSet<String>,
    seen_states: BTreeSet<u64>,
    seen_failures: BTreeSet<String>,
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

        fs::create_dir_all(dir)?;
        let id = self.retained.len();
        let path = dir.join(format!("seed-{id:04}.json"));
        fs::write(&path, serde_json::to_vec_pretty(&seed)?)?;
        self.retained.push(RetainedSeed {
            id,
            seed,
            observation,
            path,
        });
        Ok(true)
    }

    /// Retained seeds in insertion order.
    pub fn retained(&self) -> &[RetainedSeed] {
        &self.retained
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
}
