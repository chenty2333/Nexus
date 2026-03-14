#![forbid(unsafe_code)]

//! Host-side concurrent seed runner and corpus triage for Axle.

pub mod corpus;
pub mod guest;
pub mod model;
pub mod qemu;
pub mod seed;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use axle_conformance::contracts::{build_concurrency_coverage_report, load_contract_catalog};
    use tempfile::tempdir;

    use crate::corpus::Corpus;
    use crate::model::run_seed;
    use crate::seed::ConcurrentSeed;

    fn contracts_file() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../specs/conformance/contracts.toml")
    }

    #[test]
    fn base_corpus_covers_seeded_concurrency_contracts() {
        let temp = tempdir().unwrap();
        let mut corpus = Corpus::new();
        for seed in ConcurrentSeed::base_corpus(32) {
            let observation = run_seed(&seed);
            let _ = corpus.consider(temp.path(), seed, observation).unwrap();
        }
        let catalog = load_contract_catalog(&contracts_file()).unwrap();
        let report = build_concurrency_coverage_report(&catalog, &corpus.contract_observations());
        assert!(report.uncovered_hooks.is_empty(), "{report:#?}");
        assert!(report.uncovered_states.is_empty(), "{report:#?}");
        assert!(report.uncovered_failures.is_empty(), "{report:#?}");
    }
}
