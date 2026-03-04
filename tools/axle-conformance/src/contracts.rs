use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::model::ScenarioSpec;

/// Contract strictness level.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContractLevel {
    Must,
    Should,
    May,
}

/// One semantic contract entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSpec {
    pub id: String,
    pub level: ContractLevel,
    #[serde(default)]
    pub description: String,
}

/// Top-level catalog loaded from `contracts.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCatalog {
    pub schema_version: u32,
    pub contracts: Vec<ContractSpec>,
}

/// Coverage and linkage report for contract bindings.
#[derive(Debug, Clone)]
pub struct CoverageReport {
    pub total_contracts: usize,
    pub total_must: usize,
    pub covered_must: usize,
    pub uncovered_must: Vec<String>,
    pub unknown_contract_refs: Vec<(String, String)>,
    pub mapping: BTreeMap<String, Vec<String>>,
}

pub fn load_contract_catalog(path: &Path) -> Result<ContractCatalog> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let catalog: ContractCatalog =
        toml::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;

    if catalog.schema_version == 0 {
        bail!("invalid schema_version=0 in {}", path.display());
    }

    if catalog.contracts.is_empty() {
        bail!("contracts catalog is empty: {}", path.display());
    }

    let mut ids = BTreeSet::new();
    for contract in &catalog.contracts {
        if contract.id.trim().is_empty() {
            bail!("contracts catalog has empty id in {}", path.display());
        }
        if !ids.insert(contract.id.clone()) {
            bail!(
                "duplicate contract id '{}' in {}",
                contract.id,
                path.display()
            );
        }
    }

    Ok(catalog)
}

pub fn build_coverage_report(
    catalog: &ContractCatalog,
    scenarios: &BTreeMap<String, ScenarioSpec>,
) -> CoverageReport {
    let known_ids: BTreeSet<String> = catalog.contracts.iter().map(|c| c.id.clone()).collect();

    let mut mapping: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut unknown_contract_refs = Vec::new();

    for scenario in scenarios.values() {
        for contract_id in &scenario.contracts {
            if known_ids.contains(contract_id) {
                mapping
                    .entry(contract_id.clone())
                    .or_default()
                    .push(scenario.id.clone());
            } else {
                unknown_contract_refs.push((scenario.id.clone(), contract_id.clone()));
            }
        }
    }

    for scenarios_for_contract in mapping.values_mut() {
        scenarios_for_contract.sort();
        scenarios_for_contract.dedup();
    }

    let mut total_must = 0usize;
    let mut covered_must = 0usize;
    let mut uncovered_must = Vec::new();

    for contract in &catalog.contracts {
        if contract.level == ContractLevel::Must {
            total_must += 1;
            if mapping.get(&contract.id).is_some_and(|v| !v.is_empty()) {
                covered_must += 1;
            } else {
                uncovered_must.push(contract.id.clone());
            }
        }
    }

    CoverageReport {
        total_contracts: catalog.contracts.len(),
        total_must,
        covered_must,
        uncovered_must,
        unknown_contract_refs,
        mapping,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_detects_unknown_and_uncovered_must() {
        let catalog = ContractCatalog {
            schema_version: 1,
            contracts: vec![
                ContractSpec {
                    id: "must.a".into(),
                    level: ContractLevel::Must,
                    description: String::new(),
                },
                ContractSpec {
                    id: "must.b".into(),
                    level: ContractLevel::Must,
                    description: String::new(),
                },
            ],
        };

        let mut scenarios = BTreeMap::new();
        scenarios.insert(
            "s1".into(),
            ScenarioSpec {
                id: "s1".into(),
                description: String::new(),
                tags: vec![],
                timeout_ms: 100,
                command: vec!["true".into()],
                expect: vec![],
                forbid: vec![],
                contracts: vec!["must.a".into(), "unknown.x".into()],
                assertions: None,
                elf_check: None,
            },
        );

        let report = build_coverage_report(&catalog, &scenarios);
        assert_eq!(report.total_must, 2);
        assert_eq!(report.covered_must, 1);
        assert_eq!(report.uncovered_must, vec!["must.b".to_string()]);
        assert_eq!(report.unknown_contract_refs.len(), 1);
    }
}
