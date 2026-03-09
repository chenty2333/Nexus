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

/// Concurrent seed system family used by the host-side harness.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConcurrencySystem {
    WaitPortTimer,
    FutexFault,
    ChannelHandle,
}

impl ConcurrencySystem {
    /// Stable CLI/report string for this system.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WaitPortTimer => "wait_port_timer",
            Self::FutexFault => "futex_fault",
            Self::ChannelHandle => "channel_handle",
        }
    }
}

/// Stable semantic hook class surfaced by the concurrent harness.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConcurrencyHookClass {
    WaiterLinked,
    SignalUpdatedBeforeWake,
    PortReserveExhausted,
    TimerBeforeFire,
    FutexRequeueBeforeMove,
    FutexRequeueAfterMove,
    FaultLeaderClaimed,
    FaultHeavyPrepareBeforeCommit,
    FaultTxBeforeCommit,
    ChannelCloseBeforeReadDrain,
    HandleReplaceBeforePublish,
}

impl ConcurrencyHookClass {
    /// Stable CLI/report string for this hook class.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WaiterLinked => "waiter_linked",
            Self::SignalUpdatedBeforeWake => "signal_updated_before_wake",
            Self::PortReserveExhausted => "port_reserve_exhausted",
            Self::TimerBeforeFire => "timer_before_fire",
            Self::FutexRequeueBeforeMove => "futex_requeue_before_move",
            Self::FutexRequeueAfterMove => "futex_requeue_after_move",
            Self::FaultLeaderClaimed => "fault_leader_claimed",
            Self::FaultHeavyPrepareBeforeCommit => "fault_heavy_prepare_before_commit",
            Self::FaultTxBeforeCommit => "fault_tx_before_commit",
            Self::ChannelCloseBeforeReadDrain => "channel_close_before_read_drain",
            Self::HandleReplaceBeforePublish => "handle_replace_before_publish",
        }
    }
}

/// Stable abstract state projection surfaced by the concurrent harness.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConcurrencyStateProjection {
    WaitPortTimerBlockedWaiters,
    WaitPortTimerPortQueue,
    WaitPortTimerTimerSignals,
    WaitPortTimerObjectSignals,
    FutexFaultWaitQueues,
    FutexFaultInflightShape,
    FutexFaultOwnership,
    ChannelHandleWaiters,
    ChannelHandleEndpoints,
    ChannelHandleHandleTable,
}

impl ConcurrencyStateProjection {
    /// Stable CLI/report string for this state projection.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WaitPortTimerBlockedWaiters => "wait_port_timer_blocked_waiters",
            Self::WaitPortTimerPortQueue => "wait_port_timer_port_queue",
            Self::WaitPortTimerTimerSignals => "wait_port_timer_timer_signals",
            Self::WaitPortTimerObjectSignals => "wait_port_timer_object_signals",
            Self::FutexFaultWaitQueues => "futex_fault_wait_queues",
            Self::FutexFaultInflightShape => "futex_fault_inflight_shape",
            Self::FutexFaultOwnership => "futex_fault_ownership",
            Self::ChannelHandleWaiters => "channel_handle_waiters",
            Self::ChannelHandleEndpoints => "channel_handle_endpoints",
            Self::ChannelHandleHandleTable => "channel_handle_handle_table",
        }
    }
}

/// Contract metadata for the concurrent seed harness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ContractConcurrencySpec {
    /// The contract is intentionally not modeled by the current host-side harness.
    NotApplicable { reason: String },
    /// The contract should be hit by retained seeds in the specified system family.
    Seeded {
        system: ConcurrencySystem,
        hook_classes: Vec<ConcurrencyHookClass>,
        state_projections: Vec<ConcurrencyStateProjection>,
        expected_failure_kinds: Vec<String>,
    },
}

/// One semantic contract entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSpec {
    pub id: String,
    pub level: ContractLevel,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub concurrency: Option<ContractConcurrencySpec>,
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

/// Concurrent coverage observed for one harness system family.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConcurrencyObservation {
    #[serde(default)]
    pub hook_classes: BTreeSet<ConcurrencyHookClass>,
    #[serde(default)]
    pub state_projections: BTreeSet<ConcurrencyStateProjection>,
    #[serde(default)]
    pub failure_kinds: BTreeSet<String>,
}

/// One uncovered contract -> hook-class binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConcurrencyHookGap {
    pub contract_id: String,
    pub system: ConcurrencySystem,
    pub hook_class: ConcurrencyHookClass,
}

/// One uncovered contract -> state-projection binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConcurrencyStateGap {
    pub contract_id: String,
    pub system: ConcurrencySystem,
    pub state_projection: ConcurrencyStateProjection,
}

/// One uncovered contract -> expected-failure-kind binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConcurrencyFailureGap {
    pub contract_id: String,
    pub system: ConcurrencySystem,
    pub failure_kind: String,
}

/// Report that maps retained-seed concurrent coverage back to contract metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConcurrencyCoverageReport {
    pub total_seeded_contracts: usize,
    pub covered_seeded_contracts: usize,
    pub uncovered_hooks: Vec<ConcurrencyHookGap>,
    pub uncovered_states: Vec<ConcurrencyStateGap>,
    pub uncovered_failures: Vec<ConcurrencyFailureGap>,
}

pub fn load_contract_catalog(path: &Path) -> Result<ContractCatalog> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let catalog: ContractCatalog =
        toml::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;

    validate_contract_catalog(&catalog, &path.display().to_string())?;

    Ok(catalog)
}

fn validate_contract_catalog(catalog: &ContractCatalog, source: &str) -> Result<()> {
    if catalog.schema_version == 0 {
        bail!("invalid schema_version=0 in {source}");
    }

    if catalog.contracts.is_empty() {
        bail!("contracts catalog is empty: {source}");
    }

    let mut ids = BTreeSet::new();
    for contract in &catalog.contracts {
        if contract.id.trim().is_empty() {
            bail!("contracts catalog has empty id in {source}");
        }
        if !ids.insert(contract.id.clone()) {
            bail!("duplicate contract id '{}' in {source}", contract.id);
        }
        validate_contract_concurrency(contract, source)?;
    }

    Ok(())
}

fn validate_contract_concurrency(contract: &ContractSpec, source: &str) -> Result<()> {
    let Some(concurrency) = contract.concurrency.as_ref() else {
        if contract.level == ContractLevel::Must {
            bail!(
                "MUST contract '{}' missing concurrency metadata in {source}",
                contract.id
            );
        }
        return Ok(());
    };

    match concurrency {
        ContractConcurrencySpec::NotApplicable { reason } => {
            if reason.trim().is_empty() {
                bail!(
                    "contract '{}' has empty concurrency not_applicable reason in {source}",
                    contract.id
                );
            }
        }
        ContractConcurrencySpec::Seeded {
            hook_classes,
            state_projections,
            expected_failure_kinds,
            ..
        } => {
            if hook_classes.is_empty() {
                bail!(
                    "contract '{}' seeded concurrency metadata has empty hook_classes in {source}",
                    contract.id
                );
            }
            if state_projections.is_empty() {
                bail!(
                    "contract '{}' seeded concurrency metadata has empty state_projections in {source}",
                    contract.id
                );
            }
            if expected_failure_kinds.is_empty() {
                bail!(
                    "contract '{}' seeded concurrency metadata has empty expected_failure_kinds in {source}",
                    contract.id
                );
            }
            ensure_unique(
                hook_classes.iter().copied(),
                "hook_classes",
                &contract.id,
                source,
            )?;
            ensure_unique(
                state_projections.iter().copied(),
                "state_projections",
                &contract.id,
                source,
            )?;
            let mut failures = BTreeSet::new();
            for kind in expected_failure_kinds {
                if kind.trim().is_empty() {
                    bail!(
                        "contract '{}' seeded concurrency metadata has empty failure kind in {source}",
                        contract.id
                    );
                }
                if !failures.insert(kind.clone()) {
                    bail!(
                        "contract '{}' seeded concurrency metadata has duplicate failure kind '{}' in {source}",
                        contract.id,
                        kind
                    );
                }
            }
        }
    }

    Ok(())
}

fn ensure_unique<T>(
    values: impl IntoIterator<Item = T>,
    field: &str,
    contract_id: &str,
    source: &str,
) -> Result<()>
where
    T: Ord + core::fmt::Debug,
{
    let mut seen = BTreeSet::new();
    for value in values {
        if seen.contains(&value) {
            bail!(
                "contract '{}' seeded concurrency metadata has duplicate {} entry '{:?}' in {}",
                contract_id,
                field,
                value,
                source
            );
        }
        let _ = seen.insert(value);
    }
    Ok(())
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

pub fn build_concurrency_coverage_report(
    catalog: &ContractCatalog,
    observations: &BTreeMap<ConcurrencySystem, ConcurrencyObservation>,
) -> ConcurrencyCoverageReport {
    let mut total_seeded_contracts = 0usize;
    let mut covered_seeded_contracts = 0usize;
    let mut uncovered_hooks = Vec::new();
    let mut uncovered_states = Vec::new();
    let mut uncovered_failures = Vec::new();

    for contract in &catalog.contracts {
        let Some(ContractConcurrencySpec::Seeded {
            system,
            hook_classes,
            state_projections,
            expected_failure_kinds,
        }) = contract.concurrency.as_ref()
        else {
            continue;
        };

        total_seeded_contracts += 1;
        let observed = observations.get(system).cloned().unwrap_or_default();
        let mut covered = true;

        for hook_class in hook_classes {
            if !observed.hook_classes.contains(hook_class) {
                covered = false;
                uncovered_hooks.push(ConcurrencyHookGap {
                    contract_id: contract.id.clone(),
                    system: *system,
                    hook_class: *hook_class,
                });
            }
        }

        for state_projection in state_projections {
            if !observed.state_projections.contains(state_projection) {
                covered = false;
                uncovered_states.push(ConcurrencyStateGap {
                    contract_id: contract.id.clone(),
                    system: *system,
                    state_projection: *state_projection,
                });
            }
        }

        for failure_kind in expected_failure_kinds {
            if !observed.failure_kinds.contains(failure_kind) {
                covered = false;
                uncovered_failures.push(ConcurrencyFailureGap {
                    contract_id: contract.id.clone(),
                    system: *system,
                    failure_kind: failure_kind.clone(),
                });
            }
        }

        if covered {
            covered_seeded_contracts += 1;
        }
    }

    uncovered_hooks.sort();
    uncovered_states.sort();
    uncovered_failures.sort();

    ConcurrencyCoverageReport {
        total_seeded_contracts,
        covered_seeded_contracts,
        uncovered_hooks,
        uncovered_states,
        uncovered_failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_seeded_concurrency() -> ContractConcurrencySpec {
        ContractConcurrencySpec::Seeded {
            system: ConcurrencySystem::WaitPortTimer,
            hook_classes: vec![ConcurrencyHookClass::WaiterLinked],
            state_projections: vec![ConcurrencyStateProjection::WaitPortTimerPortQueue],
            expected_failure_kinds: vec!["hang.wait_port_timer".into()],
        }
    }

    #[test]
    fn coverage_detects_unknown_and_uncovered_must() {
        let catalog = ContractCatalog {
            schema_version: 1,
            contracts: vec![
                ContractSpec {
                    id: "must.a".into(),
                    level: ContractLevel::Must,
                    description: String::new(),
                    concurrency: Some(sample_seeded_concurrency()),
                },
                ContractSpec {
                    id: "must.b".into(),
                    level: ContractLevel::Must,
                    description: String::new(),
                    concurrency: Some(ContractConcurrencySpec::NotApplicable {
                        reason: "syscall-only".into(),
                    }),
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

    #[test]
    fn validate_requires_concurrency_metadata_for_must() {
        let catalog = ContractCatalog {
            schema_version: 1,
            contracts: vec![ContractSpec {
                id: "must.a".into(),
                level: ContractLevel::Must,
                description: String::new(),
                concurrency: None,
            }],
        };
        let err = validate_contract_catalog(&catalog, "inline").unwrap_err();
        assert!(err.to_string().contains("missing concurrency metadata"));
    }

    #[test]
    fn concurrency_report_detects_missing_hook_state_and_failure() {
        let catalog = ContractCatalog {
            schema_version: 1,
            contracts: vec![ContractSpec {
                id: "must.wait".into(),
                level: ContractLevel::Must,
                description: String::new(),
                concurrency: Some(ContractConcurrencySpec::Seeded {
                    system: ConcurrencySystem::WaitPortTimer,
                    hook_classes: vec![ConcurrencyHookClass::WaiterLinked],
                    state_projections: vec![ConcurrencyStateProjection::WaitPortTimerPortQueue],
                    expected_failure_kinds: vec!["hang.wait_port_timer".into()],
                }),
            }],
        };
        let observations = BTreeMap::new();
        let report = build_concurrency_coverage_report(&catalog, &observations);
        assert_eq!(report.total_seeded_contracts, 1);
        assert_eq!(report.covered_seeded_contracts, 0);
        assert_eq!(report.uncovered_hooks.len(), 1);
        assert_eq!(report.uncovered_states.len(), 1);
        assert_eq!(report.uncovered_failures.len(), 1);
    }

    #[test]
    fn toml_parses_seeded_concurrency_metadata() {
        let raw = r#"
schema_version = 1

[[contracts]]
id = "must.wait"
level = "must"
description = "sample"
[contracts.concurrency]
mode = "seeded"
system = "wait_port_timer"
hook_classes = ["waiter_linked"]
state_projections = ["wait_port_timer_port_queue"]
expected_failure_kinds = ["hang.wait_port_timer"]
"#;
        let catalog: ContractCatalog = toml::from_str(raw).unwrap();
        validate_contract_catalog(&catalog, "inline").unwrap();
        match catalog.contracts[0].concurrency.as_ref().unwrap() {
            ContractConcurrencySpec::Seeded { system, .. } => {
                assert_eq!(*system, ConcurrencySystem::WaitPortTimer);
            }
            ContractConcurrencySpec::NotApplicable { .. } => panic!("expected seeded metadata"),
        }
    }
}
