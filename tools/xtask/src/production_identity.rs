use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::path::{Component, Path};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const SCHEMA: &str = "nexus.research.production-identity.v1";
const SUMMARY_SCHEMA: &str = "nexus.research.production-identity.summary.v1";
const COMMAND: &str = "./x research production-identity";
const SPEC: &str = "ProductionIdentityCser";
const OUTPUT_DIRECTORY: &str = "target/research/production-identity";
const PLUSCAL_LOG: &str = "target/research/production-identity/pluscal.log";
const TLC_LOG: &str = "target/research/production-identity/tlc.log";
const SUMMARY_PATH: &str = "target/research/production-identity/summary.txt";
const RECEIPT_PATH: &str = "target/research/production-identity/receipt.json";
const ACTOR_BOUNDARY: &str = "abstract 2/4-CPU Service/Kernel/IRQ identities";
const BOUNDEDNESS_STATEMENT: &str = "Abstract 2/4-CPU actor identities only; not OSTD SpinLock, IRQ delivery, memory-ordering, or real SMP evidence.";

const FROZEN_V0_1_SPECS: [&str; 12] = [
    "Cser",
    "PagerCser",
    "IoCser",
    "PersonalityCser",
    "PersonalityFutexCser",
    "PersonalityFutexRequeueCser",
    "PersonalityReadinessCser",
    "PersonalityExecCser",
    "RuntimeFsCser",
    "RuntimeNetCser",
    "CompositionCser",
    "LinuxIoCompositionCser",
];

const SOURCE_FILES: [&str; 16] = [
    "x",
    "Dockerfile",
    "rust-toolchain.toml",
    "tools/xtask/Cargo.toml",
    "tools/xtask/Cargo.lock",
    "tools/xtask/src/main.rs",
    "tools/xtask/src/production_identity.rs",
    "specs/cser/check.sh",
    "specs/cser/ProductionIdentityCser.tla",
    "specs/cser/ProductionIdentityCserSafetyMC.cfg",
    "specs/cser/ProductionIdentityCserSmp4SafetyMC.cfg",
    "specs/cser/ProductionIdentityCserActionMC.cfg",
    "specs/cser/ProductionIdentityCserProgressMC.cfg",
    "specs/cser/PRODUCTION_IDENTITY.md",
    "specs/cser/README.md",
    "docs/rfcs/0001-production-identity.md",
];

#[derive(Clone, Copy)]
struct ConfigurationExpectation {
    config: &'static str,
    heading: &'static str,
    generated: u64,
    distinct: u64,
    depth: u64,
    property_mode: &'static str,
}

const CONFIGURATIONS: [ConfigurationExpectation; 4] = [
    ConfigurationExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        heading: "ProductionIdentityCser 2-CPU-actor safety graph",
        generated: 4_793,
        distinct: 3_396,
        depth: 33,
        property_mode: "safety",
    },
    ConfigurationExpectation {
        config: "ProductionIdentityCserSmp4SafetyMC.cfg",
        heading: "ProductionIdentityCser 4-CPU-actor safety graph",
        generated: 4_793,
        distinct: 3_396,
        depth: 33,
        property_mode: "safety",
    },
    ConfigurationExpectation {
        config: "ProductionIdentityCserActionMC.cfg",
        heading: "ProductionIdentityCser action properties",
        generated: 4_793,
        distinct: 3_396,
        depth: 33,
        property_mode: "action-properties",
    },
    ConfigurationExpectation {
        config: "ProductionIdentityCserProgressMC.cfg",
        heading: "ProductionIdentityCser conditional kernel progress",
        generated: 3_356,
        distinct: 2_670,
        depth: 32,
        property_mode: "conditional-progress-5-temporal-branches",
    },
];

#[derive(Clone, Copy)]
struct WitnessExpectation {
    config: &'static str,
    invariant: &'static str,
    description: &'static str,
}

const WITNESSES: [WitnessExpectation; 8] = [
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "IdentityPreservingReadAbsent",
        description: "workload-created identities survive one same-effect block read and root closure",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "FilesystemCrashAdoptAbsent",
        description: "filesystem crash/rebind/adopt changes only the current domain binding",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "CommitWinsRevokeRaceAbsent",
        description: "device batch commit wins the shared root gate before revocation",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "RevokeWinsCommitRaceAbsent",
        description: "root revocation wins the shared gate and aborts every uncommitted descendant",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "ResetIotlbSameEffectAbsent",
        description: "reset and IOTLB timeouts retain the same effect through retry and closure",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "CrossRegistryGenerationRejectAbsent",
        description: "foreign-registry and stale-device-generation inputs reject without semantic mutation",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "ActorSeparationAbsent",
        description: "2-CPU abstract service/kernel/IRQ roles retain one identity chain",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSmp4SafetyMC.cfg",
        invariant: "ActorSeparationAbsent",
        description: "4-CPU abstract service/kernel/IRQ roles retain one identity chain",
    },
];

#[derive(Clone, Copy)]
enum ExpectedSection {
    Configuration(usize),
    Witness(usize),
}

const SECTION_ORDER: [ExpectedSection; 12] = [
    ExpectedSection::Configuration(0),
    ExpectedSection::Configuration(1),
    ExpectedSection::Witness(0),
    ExpectedSection::Witness(1),
    ExpectedSection::Witness(2),
    ExpectedSection::Witness(3),
    ExpectedSection::Witness(4),
    ExpectedSection::Witness(5),
    ExpectedSection::Witness(6),
    ExpectedSection::Witness(7),
    ExpectedSection::Configuration(2),
    ExpectedSection::Configuration(3),
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationReceipt {
    config: String,
    status: String,
    generated: u64,
    distinct: u64,
    depth: u64,
    states_left_on_queue: u64,
    property_mode: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WitnessReceipt {
    config: String,
    invariant: String,
    description: String,
    status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseBoundary {
    accepted_release: String,
    accepted_specifications: usize,
    successor_in_v0_1_catalog: bool,
    successor_artifacts_in_v0_1_manifest: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Logs {
    pluscal_translation: String,
    tlc: String,
    summary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Digests {
    pluscal_translation_sha256: String,
    tlc_sha256: String,
    summary_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    status: String,
    prospective: bool,
    command: String,
    revision: String,
    worktree_dirty: bool,
    source_fingerprint: String,
    source_files: Vec<String>,
    translation_current: bool,
    full_configurations: usize,
    configurations: Vec<ConfigurationReceipt>,
    reachability_witnesses: usize,
    witnesses: Vec<WitnessReceipt>,
    actor_boundary: String,
    boundedness_statement: String,
    real_ostd_smp_claimed: bool,
    release_boundary: ReleaseBoundary,
    generated_unix_seconds: u64,
    logs: Logs,
    digests: Digests,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GraphStats {
    generated: u64,
    distinct: u64,
    left_on_queue: u64,
    depth: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct LogSummary {
    configurations: Vec<ConfigurationReceipt>,
    witnesses: Vec<WitnessReceipt>,
}

pub(crate) fn run(root: &Path, release_specs: &[&str]) -> Result<()> {
    validate_release_boundary(release_specs)?;

    let output = root.join(OUTPUT_DIRECTORY);
    let output_parent = output
        .parent()
        .ok_or("production-identity output has no parent")?;
    fs::create_dir_all(output_parent)?;
    let _lock = super::SpecRunLock::acquire(&output_parent.join(".production-identity.lock"))?;
    fs::create_dir_all(&output)?;
    clear_previous_outputs(root)?;

    let revision_before = git_text(root, &["rev-parse", "HEAD"])?;
    let source_before = fingerprint_paths(root, &SOURCE_FILES)?;
    let jar = super::tla2tools_jar()?;
    let source_cser_dir = root.join("specs/cser");
    let workspace = super::IsolatedSpecWorkspace::create(&source_cser_dir)?;

    super::pluscal_translation_is_current(
        &source_cser_dir,
        workspace.cser_dir(),
        &jar,
        SPEC,
        &root.join(PLUSCAL_LOG),
    )?;

    super::section("run prospective ProductionIdentityCser research gate");
    let mut command = Command::new("sh");
    command
        .current_dir(workspace.cser_dir())
        .env("TLA2TOOLS_JAR", &jar)
        .env("TMPDIR", workspace.temp_dir())
        .arg(workspace.cser_dir().join("check.sh"))
        .arg(SPEC);
    super::run_bounded_logged_quiet(
        &mut command,
        &root.join(TLC_LOG),
        Duration::from_secs(900),
        16 * 1024 * 1024,
    )?;

    let transcript = fs::read_to_string(root.join(TLC_LOG))?;
    let log_summary = validate_tlc_log(&transcript)?;
    let revision_after = git_text(root, &["rev-parse", "HEAD"])?;
    let source_after = fingerprint_paths(root, &SOURCE_FILES)?;
    if revision_before != revision_after || source_before != source_after {
        return Err(format!(
            "production-identity sources changed during verification: revision {revision_before}->{revision_after}, fingerprint {source_before}->{source_after}"
        )
        .into());
    }

    let worktree_dirty = !git_bytes(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?
    .is_empty();
    let summary = summary_text(&revision_after, &source_after, worktree_dirty);
    atomic_write(&root.join(SUMMARY_PATH), summary.as_bytes())?;

    let receipt = Receipt {
        schema: String::from(SCHEMA),
        status: String::from("passed"),
        prospective: true,
        command: String::from(COMMAND),
        revision: revision_after,
        worktree_dirty,
        source_fingerprint: source_after,
        source_files: SOURCE_FILES
            .iter()
            .map(|path| String::from(*path))
            .collect(),
        translation_current: true,
        full_configurations: log_summary.configurations.len(),
        configurations: log_summary.configurations,
        reachability_witnesses: log_summary.witnesses.len(),
        witnesses: log_summary.witnesses,
        actor_boundary: String::from(ACTOR_BOUNDARY),
        boundedness_statement: String::from(BOUNDEDNESS_STATEMENT),
        real_ostd_smp_claimed: false,
        release_boundary: ReleaseBoundary {
            accepted_release: String::from("v0.1.0"),
            accepted_specifications: release_specs.len(),
            successor_in_v0_1_catalog: false,
            successor_artifacts_in_v0_1_manifest: false,
        },
        generated_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        logs: Logs {
            pluscal_translation: String::from(PLUSCAL_LOG),
            tlc: String::from(TLC_LOG),
            summary: String::from(SUMMARY_PATH),
        },
        digests: Digests {
            pluscal_translation_sha256: sha256_file(&root.join(PLUSCAL_LOG))?,
            tlc_sha256: sha256_file(&root.join(TLC_LOG))?,
            summary_sha256: sha256_file(&root.join(SUMMARY_PATH))?,
        },
    };
    validate_receipt(&receipt)?;
    let mut encoded = serde_json::to_vec_pretty(&receipt)?;
    encoded.push(b'\n');
    atomic_write(&root.join(RECEIPT_PATH), &encoded)?;

    println!(
        "PRODUCTION IDENTITY RESEARCH PASS configurations={} witnesses={} receipt={}",
        receipt.full_configurations, receipt.reachability_witnesses, RECEIPT_PATH
    );
    println!("{BOUNDEDNESS_STATEMENT}");
    Ok(())
}

pub(crate) fn validate_release_boundary(release_specs: &[&str]) -> Result<()> {
    if release_specs != FROZEN_V0_1_SPECS {
        return Err(format!(
            "the accepted v0.1.0 specification catalog changed: expected {:?}, found {release_specs:?}",
            FROZEN_V0_1_SPECS
        )
        .into());
    }
    if release_specs.contains(&SPEC) {
        return Err(
            "ProductionIdentityCser must remain outside the accepted v0.1.0 catalog".into(),
        );
    }
    Ok(())
}

fn clear_previous_outputs(root: &Path) -> Result<()> {
    for relative in [PLUSCAL_LOG, TLC_LOG, SUMMARY_PATH, RECEIPT_PATH] {
        match fs::remove_file(root.join(relative)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "remove stale production-identity artifact {relative}: {error}"
                )
                .into());
            }
        }
    }
    Ok(())
}

fn validate_tlc_log(log: &str) -> Result<LogSummary> {
    let lines: Vec<_> = log.lines().collect();
    let starts: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("==> ProductionIdentityCser "))
        .map(|(index, line)| (index, *line))
        .collect();
    let expected_headings: Vec<_> = SECTION_ORDER.iter().map(expected_heading).collect();
    let actual_headings: Vec<_> = starts
        .iter()
        .map(|(_, heading)| String::from(*heading))
        .collect();
    if actual_headings != expected_headings {
        return Err(format!(
            "ProductionIdentityCser section population or order differs: expected {expected_headings:?}, found {actual_headings:?}"
        )
        .into());
    }

    let expected_coverage: Vec<_> = WITNESSES
        .iter()
        .map(|witness| format!("COVERAGE_RESULT PASS {}", witness.description))
        .collect();
    let actual_coverage: Vec<_> = lines
        .iter()
        .filter(|line| line.starts_with("COVERAGE_RESULT "))
        .map(|line| String::from(*line))
        .collect();
    if actual_coverage != expected_coverage {
        return Err(format!(
            "ProductionIdentityCser coverage population or order differs: expected {expected_coverage:?}, found {actual_coverage:?}"
        )
        .into());
    }

    let completion_marker = "Model checking completed. No error has been found.";
    let completion_count = lines
        .iter()
        .filter(|line| **line == completion_marker)
        .count();
    if completion_count != CONFIGURATIONS.len() {
        return Err(format!(
            "ProductionIdentityCser has {completion_count} complete TLC markers; expected {}",
            CONFIGURATIONS.len()
        )
        .into());
    }

    let mut configurations = Vec::with_capacity(CONFIGURATIONS.len());
    let mut witnesses = Vec::with_capacity(WITNESSES.len());
    for (position, section) in SECTION_ORDER.iter().enumerate() {
        let start = starts[position].0;
        let end = starts
            .get(position + 1)
            .map(|(index, _)| *index)
            .unwrap_or(lines.len());
        let block = &lines[start..end];
        match section {
            ExpectedSection::Configuration(index) => {
                let expected = CONFIGURATIONS[*index];
                configurations.push(validate_configuration_block(expected, block)?);
            }
            ExpectedSection::Witness(index) => {
                let expected = WITNESSES[*index];
                witnesses.push(validate_witness_block(expected, block)?);
            }
        }
    }

    let expected_configurations: Vec<_> =
        CONFIGURATIONS.iter().map(configuration_receipt).collect();
    if configurations != expected_configurations {
        return Err("ProductionIdentityCser configuration receipts differ from the frozen four-graph contract".into());
    }
    let expected_witnesses: Vec<_> = WITNESSES.iter().map(witness_receipt).collect();
    if witnesses != expected_witnesses {
        return Err(
            "ProductionIdentityCser witness receipts differ from the frozen eight-witness contract"
                .into(),
        );
    }

    Ok(LogSummary {
        configurations,
        witnesses,
    })
}

fn expected_heading(section: &ExpectedSection) -> String {
    match section {
        ExpectedSection::Configuration(index) => {
            format!("==> {}", CONFIGURATIONS[*index].heading)
        }
        ExpectedSection::Witness(index) => {
            format!("==> {SPEC} reachability: {}", WITNESSES[*index].description)
        }
    }
}

fn validate_configuration_block(
    expected: ConfigurationExpectation,
    block: &[&str],
) -> Result<ConfigurationReceipt> {
    let completion_marker = "Model checking completed. No error has been found.";
    let completions = block
        .iter()
        .filter(|line| **line == completion_marker)
        .count();
    if completions != 1 {
        return Err(format!(
            "{} has {completions} complete TLC markers; expected one",
            expected.config
        )
        .into());
    }
    if block
        .iter()
        .any(|line| line.starts_with("COVERAGE_RESULT "))
    {
        return Err(format!("{} contains a fabricated coverage marker", expected.config).into());
    }

    let state_lines: Vec<_> = block
        .iter()
        .filter(|line| {
            line.as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_digit())
                && line.contains(" states generated, ")
                && line.contains(" states left on queue.")
        })
        .collect();
    if state_lines.len() != 1 {
        return Err(format!(
            "{} has {} final state-population lines; expected one",
            expected.config,
            state_lines.len()
        )
        .into());
    }
    let (generated, distinct, left_on_queue) = parse_state_population(state_lines[0])?;
    let depth_lines: Vec<_> = block
        .iter()
        .filter(|line| line.starts_with("The depth of the complete state graph search is "))
        .collect();
    if depth_lines.len() != 1 {
        return Err(format!(
            "{} has {} complete-depth lines; expected one",
            expected.config,
            depth_lines.len()
        )
        .into());
    }
    let depth = parse_depth(depth_lines[0])?;
    let observed = GraphStats {
        generated,
        distinct,
        left_on_queue,
        depth,
    };
    let required = GraphStats {
        generated: expected.generated,
        distinct: expected.distinct,
        left_on_queue: 0,
        depth: expected.depth,
    };
    if observed != required {
        return Err(format!(
            "{} graph population differs: expected {required:?}, found {observed:?}",
            expected.config
        )
        .into());
    }
    if expected.config == "ProductionIdentityCserProgressMC.cfg" {
        let temporal_branches = block
            .iter()
            .filter(|line| {
                **line == "Implied-temporal checking--satisfiability problem has 5 branches."
            })
            .count();
        if temporal_branches != 1 {
            return Err(format!(
                "{} has {temporal_branches} five-branch temporal markers; expected one",
                expected.config
            )
            .into());
        }
    }
    Ok(configuration_receipt(&expected))
}

fn validate_witness_block(expected: WitnessExpectation, block: &[&str]) -> Result<WitnessReceipt> {
    let coverage = format!("COVERAGE_RESULT PASS {}", expected.description);
    let coverage_count = block
        .iter()
        .filter(|line| **line == coverage.as_str())
        .count();
    if coverage_count != 1 {
        return Err(format!(
            "witness {} has {coverage_count} exact coverage markers; expected one",
            expected.invariant
        )
        .into());
    }
    let invariant_marker = format!("Invariant {} is violated", expected.invariant);
    let invariant_count = block
        .iter()
        .filter(|line| line.contains(&invariant_marker))
        .count();
    if invariant_count != 1 {
        return Err(format!(
            "witness {} has {invariant_count} expected invariant violations; expected one",
            expected.invariant
        )
        .into());
    }
    if block.contains(&"Model checking completed. No error has been found.") {
        return Err(format!(
            "witness {} was mislabeled as a successful invariant graph",
            expected.invariant
        )
        .into());
    }
    Ok(witness_receipt(&expected))
}

fn parse_state_population(line: &str) -> Result<(u64, u64, u64)> {
    let (generated, remainder) = line
        .split_once(" states generated, ")
        .ok_or_else(|| format!("malformed TLC state population: {line}"))?;
    let (distinct, remainder) = remainder
        .split_once(" distinct states found, ")
        .ok_or_else(|| format!("malformed TLC distinct population: {line}"))?;
    let left = remainder
        .strip_suffix(" states left on queue.")
        .ok_or_else(|| format!("malformed TLC queue population: {line}"))?;
    Ok((
        parse_formatted_u64(generated)?,
        parse_formatted_u64(distinct)?,
        parse_formatted_u64(left)?,
    ))
}

fn parse_depth(line: &str) -> Result<u64> {
    let value = line
        .strip_prefix("The depth of the complete state graph search is ")
        .and_then(|value| value.strip_suffix('.'))
        .ok_or_else(|| format!("malformed TLC complete depth: {line}"))?;
    parse_formatted_u64(value)
}

fn parse_formatted_u64(value: &str) -> Result<u64> {
    Ok(value.replace(',', "").parse()?)
}

fn configuration_receipt(expected: &ConfigurationExpectation) -> ConfigurationReceipt {
    ConfigurationReceipt {
        config: String::from(expected.config),
        status: String::from("complete"),
        generated: expected.generated,
        distinct: expected.distinct,
        depth: expected.depth,
        states_left_on_queue: 0,
        property_mode: String::from(expected.property_mode),
    }
}

fn witness_receipt(expected: &WitnessExpectation) -> WitnessReceipt {
    WitnessReceipt {
        config: String::from(expected.config),
        invariant: String::from(expected.invariant),
        description: String::from(expected.description),
        status: String::from("reachable"),
    }
}

fn validate_receipt(receipt: &Receipt) -> Result<()> {
    if receipt.schema != SCHEMA
        || receipt.status != "passed"
        || !receipt.prospective
        || receipt.command != COMMAND
        || !receipt.translation_current
    {
        return Err(
            "production-identity receipt has an invalid identity or status boundary".into(),
        );
    }
    if receipt.actor_boundary != ACTOR_BOUNDARY
        || receipt.boundedness_statement != BOUNDEDNESS_STATEMENT
        || receipt.real_ostd_smp_claimed
    {
        return Err(
            "production-identity receipt overstates its abstract CPU-actor boundary".into(),
        );
    }
    if receipt.release_boundary
        != (ReleaseBoundary {
            accepted_release: String::from("v0.1.0"),
            accepted_specifications: FROZEN_V0_1_SPECS.len(),
            successor_in_v0_1_catalog: false,
            successor_artifacts_in_v0_1_manifest: false,
        })
    {
        return Err("production-identity receipt changed the accepted v0.1.0 boundary".into());
    }
    let configurations: Vec<_> = CONFIGURATIONS.iter().map(configuration_receipt).collect();
    if receipt.full_configurations != CONFIGURATIONS.len()
        || receipt.configurations != configurations
    {
        return Err(
            "production-identity receipt lacks the exact four complete configurations".into(),
        );
    }
    let witnesses: Vec<_> = WITNESSES.iter().map(witness_receipt).collect();
    if receipt.reachability_witnesses != WITNESSES.len() || receipt.witnesses != witnesses {
        return Err(
            "production-identity receipt lacks the exact eight reachability witnesses".into(),
        );
    }
    let source_files: Vec<_> = SOURCE_FILES
        .iter()
        .map(|path| String::from(*path))
        .collect();
    if receipt.source_files != source_files
        || !is_sha256(&receipt.source_fingerprint)
        || receipt.revision.is_empty()
    {
        return Err("production-identity receipt is not bound to the expected source set".into());
    }
    if receipt.logs
        != (Logs {
            pluscal_translation: String::from(PLUSCAL_LOG),
            tlc: String::from(TLC_LOG),
            summary: String::from(SUMMARY_PATH),
        })
        || !is_sha256(&receipt.digests.pluscal_translation_sha256)
        || !is_sha256(&receipt.digests.tlc_sha256)
        || !is_sha256(&receipt.digests.summary_sha256)
    {
        return Err("production-identity receipt has an invalid artifact binding".into());
    }
    Ok(())
}

fn summary_text(revision: &str, source_fingerprint: &str, worktree_dirty: bool) -> String {
    format!(
        "schema={SUMMARY_SCHEMA}\nstatus=passed\nprospective=true\ncommand={COMMAND}\nrevision={revision}\nworktree_dirty={worktree_dirty}\nsource_fingerprint={source_fingerprint}\ntranslation_current=true\nfull_configurations={}\nreachability_witnesses={}\naccepted_v0_1_specifications={}\nsuccessor_in_v0_1_catalog=false\nsuccessor_artifacts_in_v0_1_manifest=false\nactor_boundary={ACTOR_BOUNDARY}\nboundedness_statement={BOUNDEDNESS_STATEMENT}\nreal_ostd_smp_claimed=false\nreceipt={RECEIPT_PATH}\n",
        CONFIGURATIONS.len(),
        WITNESSES.len(),
        FROZEN_V0_1_SPECS.len(),
    )
}

fn fingerprint_paths(root: &Path, paths: &[&str]) -> Result<String> {
    let mut digest = Sha256::new();
    for relative in paths {
        let path = Path::new(relative);
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(
                format!("source fingerprint path escapes the repository: {relative}").into(),
            );
        }
        let absolute = root.join(path);
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("source fingerprint input {relative}: {error}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(
                format!("source fingerprint input is not a regular file: {relative}").into(),
            );
        }
        let first = fs::read(&absolute)?;
        let second = fs::read(&absolute)?;
        if first != second {
            return Err(
                format!("source fingerprint input changed while reading: {relative}").into(),
            );
        }
        digest_field(&mut digest, relative.as_bytes());
        digest_field(&mut digest, &first);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn digest_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    let bytes = git_bytes(root, args)?;
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}

fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git").current_dir(root).args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "git command failed with {}: git {}",
            output.status,
            args.join(" ")
        )
        .into());
    }
    Ok(output.stdout)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("artifact path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("artifact path has no UTF-8 file name: {}", path.display()))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    fs::write(&temporary, bytes)?;
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_log() -> String {
        let mut log = String::new();
        for section in SECTION_ORDER {
            log.push_str(&expected_heading(&section));
            log.push('\n');
            match section {
                ExpectedSection::Configuration(index) => {
                    let expected = CONFIGURATIONS[index];
                    if expected.config == "ProductionIdentityCserProgressMC.cfg" {
                        log.push_str(
                            "Implied-temporal checking--satisfiability problem has 5 branches.\n",
                        );
                        log.push_str(&format!(
                            "Progress(32): {} states generated, {} distinct states found, 0 states left on queue.\n",
                            expected.generated, expected.distinct
                        ));
                    }
                    log.push_str("Model checking completed. No error has been found.\n");
                    log.push_str(&format!(
                        "{} states generated, {} distinct states found, 0 states left on queue.\n",
                        expected.generated, expected.distinct
                    ));
                    log.push_str(&format!(
                        "The depth of the complete state graph search is {}.\n",
                        expected.depth
                    ));
                }
                ExpectedSection::Witness(index) => {
                    let expected = WITNESSES[index];
                    log.push_str(&format!(
                        "Error: Invariant {} is violated.\n",
                        expected.invariant
                    ));
                    log.push_str(&format!("COVERAGE_RESULT PASS {}\n", expected.description));
                }
            }
        }
        log
    }

    #[test]
    fn accepts_exact_four_configurations_and_eight_witnesses() {
        let summary = validate_tlc_log(&synthetic_log()).expect("valid research log");
        assert_eq!(summary.configurations.len(), 4);
        assert_eq!(summary.witnesses.len(), 8);
    }

    #[test]
    fn rejects_missing_duplicated_and_fabricated_witness_markers() {
        let marker = format!("COVERAGE_RESULT PASS {}", WITNESSES[0].description);

        let missing = synthetic_log().replacen(&format!("{marker}\n"), "", 1);
        assert!(validate_tlc_log(&missing).is_err());

        let duplicated = format!("{}{}\n", synthetic_log(), marker);
        assert!(validate_tlc_log(&duplicated).is_err());

        let fabricated = synthetic_log().replacen(
            &marker,
            "COVERAGE_RESULT PASS fabricated successor evidence",
            1,
        );
        assert!(validate_tlc_log(&fabricated).is_err());
    }

    #[test]
    fn rejects_reordered_sections_and_inexact_graph_populations() {
        let first = expected_heading(&ExpectedSection::Configuration(0));
        let second = expected_heading(&ExpectedSection::Configuration(1));
        let reordered = synthetic_log()
            .replacen(&first, "TEMPORARY_HEADING", 1)
            .replacen(&second, &first, 1)
            .replacen("TEMPORARY_HEADING", &second, 1);
        assert!(validate_tlc_log(&reordered).is_err());

        let population = synthetic_log().replacen(
            "4793 states generated, 3396 distinct states found",
            "4794 states generated, 3396 distinct states found",
            1,
        );
        assert!(validate_tlc_log(&population).is_err());
    }

    #[test]
    fn freezes_the_v0_1_catalog_outside_the_successor() {
        validate_release_boundary(&FROZEN_V0_1_SPECS).expect("frozen catalog");
        let mut widened = FROZEN_V0_1_SPECS.to_vec();
        widened.push(SPEC);
        assert!(validate_release_boundary(&widened).is_err());
        assert_eq!(FROZEN_V0_1_SPECS.len(), 12);
    }

    #[test]
    fn receipt_contract_forbids_real_ostd_smp_claims() {
        let configurations = CONFIGURATIONS
            .iter()
            .map(configuration_receipt)
            .collect::<Vec<_>>();
        let witnesses = WITNESSES.iter().map(witness_receipt).collect::<Vec<_>>();
        let mut receipt = Receipt {
            schema: String::from(SCHEMA),
            status: String::from("passed"),
            prospective: true,
            command: String::from(COMMAND),
            revision: String::from("revision"),
            worktree_dirty: true,
            source_fingerprint: "a".repeat(64),
            source_files: SOURCE_FILES
                .iter()
                .map(|path| String::from(*path))
                .collect(),
            translation_current: true,
            full_configurations: configurations.len(),
            configurations,
            reachability_witnesses: witnesses.len(),
            witnesses,
            actor_boundary: String::from(ACTOR_BOUNDARY),
            boundedness_statement: String::from(BOUNDEDNESS_STATEMENT),
            real_ostd_smp_claimed: false,
            release_boundary: ReleaseBoundary {
                accepted_release: String::from("v0.1.0"),
                accepted_specifications: 12,
                successor_in_v0_1_catalog: false,
                successor_artifacts_in_v0_1_manifest: false,
            },
            generated_unix_seconds: 1,
            logs: Logs {
                pluscal_translation: String::from(PLUSCAL_LOG),
                tlc: String::from(TLC_LOG),
                summary: String::from(SUMMARY_PATH),
            },
            digests: Digests {
                pluscal_translation_sha256: "b".repeat(64),
                tlc_sha256: "c".repeat(64),
                summary_sha256: "d".repeat(64),
            },
        };
        validate_receipt(&receipt).expect("bounded prospective receipt");

        receipt.real_ostd_smp_claimed = true;
        assert!(validate_receipt(&receipt).is_err());
        receipt.real_ostd_smp_claimed = false;
        receipt.boundedness_statement = String::from("real SMP evidence");
        assert!(validate_receipt(&receipt).is_err());
    }
}
