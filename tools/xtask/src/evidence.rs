use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env::VarError;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::Read as _;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

mod bundle;

pub(crate) use bundle::{verify_bundle, write_bundle};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const SCHEMA: &str = "nexus.verification.v6";
const START_SCHEMA: &str = "nexus.verification.start.v1";
const FORMAL_VERIFIER_SCHEMA: &str = "nexus.verification.formal-verifier.v1";
const MODEL_SPEC_SCHEMA: &str = "nexus.verification.model-spec.v2";
const COMPLETE_SCHEMA: &str = "nexus.verification.complete.v2";
const SENTINEL: &str = "target/verification/.stage7a-verify-start.json";
const MODEL_SPEC_RECEIPT: &str = "target/verification/.stage7a-model-spec-complete.json";
const COMPLETION_RECEIPT: &str = "target/verification/.stage7a-verify-complete.json";
const FORMAL_VERIFIER_RECEIPT: &str = "target/verification/.formal-verifier.json";
const OUTPUT: &str = "target/verification/manifest.json";
const TLA_TOOLCHAIN_ID: &str = "tlaplus-tlc-227f61b";
const TLA_TOOLCHAIN_SNAPSHOT: &str = "1.8.0-227f61b";
const TLA_TOOLCHAIN_DISTRIBUTION: &str = "vendored-snapshot";
const TLA_TOOLCHAIN_VERSION: &str = "2026.07.09.134028";
const TLA_TOOLCHAIN_SOURCE_REVISION: &str = "227f61b983d0203a06db8184da45aed421e8f1b8";
const TLA_TOOLCHAIN_INSTALLED_PATH: &str = "/opt/tla2tools/tla2tools.jar";
const TLA_TOOLCHAIN_VERSION_LINE: &str = "TLC2 Version 2026.07.09.134028 (rev: 227f61b)";
const PLUSCAL_VERSION_LINE: &str = "pcal.trans Version 1.12 of 01 July 2024";
const ENTRY_DEBUGCON_PASS: &str = "Linux futex entry debugcon assertions: PASS tasks=510+511+512+513 boundaries=pre-irq-admitted+post-irq-entry+closure-entered+identity-validated encoding=single-byte-hex bytes=16 records=16 sink=isa-debugcon mutations=6";
const TLA_TOOLCHAIN_JAR: ToolchainFileContract = ToolchainFileContract {
    path: "third_party/tlaplus/1.8.0-227f61b/tla2tools-227f61b.jar",
    bytes: 4_357_904,
    sha256: "33de7da9ce1b7fffb9d1c184021178dbb051747be48504e65c584c423721a32e",
};
const TLA_TOOLCHAIN_PROVENANCE: ToolchainFileContract = ToolchainFileContract {
    path: "third_party/tlaplus/1.8.0-227f61b/PROVENANCE.json",
    bytes: 1_388,
    sha256: "ba818b240937b61043c6203d4e23bddb87274652b1d06deb5033ca59a43a09f5",
};
const TLA_TOOLCHAIN_LICENSE: ToolchainFileContract = ToolchainFileContract {
    path: "third_party/tlaplus/1.8.0-227f61b/LICENSE.upstream",
    bytes: 1_149,
    sha256: "3fa3a845ce5eb7b9b3508701dc1aa4d084b6b2c27cbae8cd44d277d10ee411bf",
};
const TLA_TOOLCHAIN_CHECKSUM_INDEX: ToolchainFileContract = ToolchainFileContract {
    path: "third_party/tlaplus/1.8.0-227f61b/SHA256SUMS",
    bytes: 88,
    sha256: "bf43a10a47324a8e68e767f23406fc089494c53b41a26b109518f7355f3f4c40",
};
const COMPLETE_STAGES: [&str; 6] = [
    "reference-model",
    "formal-specifications",
    "system-composition",
    "same-boot-device-composition",
    "stage7b-evaluation",
    "stage7b-contribution-decision",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StartRecord {
    schema: String,
    revision: String,
    source_sha256: String,
    worktree_dirty: bool,
    invocation: String,
    nexus_rebuild: Option<String>,
    rebuild_requested: bool,
    orchestration_token_sha256: String,
    nonce: String,
    process_id: u32,
    started_unix_nanos: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceSnapshot {
    revision: String,
    source_sha256: String,
    worktree_dirty: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerificationEnvironment {
    invocation: String,
    nexus_rebuild: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GateReceipt {
    schema: String,
    revision: String,
    source_sha256: String,
    worktree_dirty: bool,
    invocation: String,
    nexus_rebuild: Option<String>,
    rebuild_requested: bool,
    orchestration_token_sha256: String,
    run_nonce: String,
    completed_unix_nanos: u128,
    stages: Vec<String>,
    prerequisite_sha256: Option<String>,
    artifacts: Vec<Artifact>,
}

#[derive(Serialize)]
struct Manifest {
    schema: &'static str,
    status: &'static str,
    command: String,
    revision: String,
    source_sha256: String,
    worktree_dirty: bool,
    nexus_rebuild: Option<String>,
    rebuild_requested: bool,
    orchestration_token_sha256: String,
    run_nonce: String,
    completion_receipt_sha256: String,
    started_unix_nanos: u128,
    generated_unix_seconds: u64,
    formal_verifier: FormalVerifierBinding,
    boundaries: Boundaries,
    specifications: Vec<String>,
    stages: Vec<Stage>,
    artifacts: Vec<Artifact>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ToolchainFileContract {
    path: &'static str,
    bytes: u64,
    sha256: &'static str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ToolchainFile {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ToolchainReceipt {
    id: String,
    snapshot: String,
    distribution: String,
    applies_to_stages: Vec<String>,
    jar: ToolchainFile,
    tlc_version: String,
    source_revision: String,
    provenance: ToolchainFile,
    license: ToolchainFile,
    checksum_index: ToolchainFile,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FormalVerifierReceipt {
    schema: String,
    start_record_sha256: String,
    revision: String,
    source_sha256: String,
    worktree_dirty: bool,
    invocation: String,
    nexus_rebuild: Option<String>,
    rebuild_requested: bool,
    orchestration_token_sha256: String,
    run_nonce: String,
    completed_unix_nanos: u128,
    toolchain: ToolchainReceipt,
    installed_path: String,
    installed_bytes: u64,
    installed_sha256: String,
    reported_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FormalVerifierBinding {
    toolchain: ToolchainReceipt,
    installed_path: String,
    runtime_receipt: Artifact,
}

fn toolchain_file(contract: ToolchainFileContract) -> ToolchainFile {
    ToolchainFile {
        path: String::from(contract.path),
        bytes: contract.bytes,
        sha256: String::from(contract.sha256),
    }
}

fn expected_toolchain_receipt() -> ToolchainReceipt {
    ToolchainReceipt {
        id: String::from(TLA_TOOLCHAIN_ID),
        snapshot: String::from(TLA_TOOLCHAIN_SNAPSHOT),
        distribution: String::from(TLA_TOOLCHAIN_DISTRIBUTION),
        applies_to_stages: vec![String::from("formal-specifications")],
        jar: toolchain_file(TLA_TOOLCHAIN_JAR),
        tlc_version: String::from(TLA_TOOLCHAIN_VERSION),
        source_revision: String::from(TLA_TOOLCHAIN_SOURCE_REVISION),
        provenance: toolchain_file(TLA_TOOLCHAIN_PROVENANCE),
        license: toolchain_file(TLA_TOOLCHAIN_LICENSE),
        checksum_index: toolchain_file(TLA_TOOLCHAIN_CHECKSUM_INDEX),
    }
}

fn toolchain_files(receipt: &ToolchainReceipt) -> [&ToolchainFile; 4] {
    [
        &receipt.jar,
        &receipt.provenance,
        &receipt.license,
        &receipt.checksum_index,
    ]
}

fn validate_toolchain_receipt(receipt: &ToolchainReceipt) -> Result<()> {
    if receipt != &expected_toolchain_receipt() {
        return Err("verification toolchain receipt differs from the pinned contract".into());
    }
    Ok(())
}

fn validate_toolchain_files(base: &Path, receipt: &ToolchainReceipt) -> Result<()> {
    validate_toolchain_receipt(receipt)?;
    for file in toolchain_files(receipt) {
        let read =
            read_regular_file_stable(&base.join(&file.path), "pinned verification toolchain file")?;
        if u64::try_from(read.bytes.len())? != file.bytes || sha256(&read.bytes) != file.sha256 {
            return Err(format!(
                "pinned verification toolchain bytes disagree with the receipt: {}",
                file.path
            )
            .into());
        }
    }
    Ok(())
}

fn validated_toolchain_receipt(base: &Path) -> Result<ToolchainReceipt> {
    let receipt = expected_toolchain_receipt();
    validate_toolchain_files(base, &receipt)?;
    Ok(receipt)
}

fn installed_formal_verifier(root: &Path) -> Result<(PathBuf, ToolchainReceipt)> {
    let toolchain = validated_toolchain_receipt(root)?;
    let installed = std::env::var_os("TLA2TOOLS_JAR")
        .ok_or("TLA2TOOLS_JAR is required to use the pinned formal verifier")?;
    let installed = PathBuf::from(installed);
    if installed != Path::new(TLA_TOOLCHAIN_INSTALLED_PATH) {
        return Err(format!(
            "formal verification must use the pinned installed path: {}",
            installed.display()
        )
        .into());
    }

    let installed_file = read_regular_file_stable(&installed, "installed formal verifier JAR")?;
    let vendored_file = read_regular_file_stable(
        &root.join(&toolchain.jar.path),
        "vendored formal verifier JAR",
    )?;
    if installed_file.bytes != vendored_file.bytes
        || u64::try_from(installed_file.bytes.len())? != toolchain.jar.bytes
        || sha256(&installed_file.bytes) != toolchain.jar.sha256
    {
        return Err("installed formal verifier does not equal the vendored JAR bytes".into());
    }
    Ok((installed, toolchain))
}

pub(crate) fn pinned_tla2tools_jar(root: &Path) -> Result<PathBuf> {
    installed_formal_verifier(root).map(|(installed, _)| installed)
}

fn capture_formal_verifier(
    root: &Path,
    start: &StartRecord,
    start_record_sha256: &str,
) -> Result<FormalVerifierReceipt> {
    if !is_sha256(start_record_sha256) {
        return Err("formal verifier start-record prerequisite is malformed".into());
    }
    let (installed, toolchain) = installed_formal_verifier(root)?;

    let output = Command::new("java")
        .arg("-cp")
        .arg(&installed)
        .args(["tlc2.TLC", "-version"])
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    let reported_version = stdout
        .lines()
        .chain(stderr.lines())
        .find(|line| !line.trim().is_empty())
        .ok_or("formal verifier version command returned no output")?;
    if reported_version != TLA_TOOLCHAIN_VERSION_LINE {
        return Err(format!(
            "installed formal verifier reported an unexpected version: {reported_version:?}"
        )
        .into());
    }

    Ok(FormalVerifierReceipt {
        schema: String::from(FORMAL_VERIFIER_SCHEMA),
        start_record_sha256: String::from(start_record_sha256),
        revision: start.revision.clone(),
        source_sha256: start.source_sha256.clone(),
        worktree_dirty: start.worktree_dirty,
        invocation: start.invocation.clone(),
        nexus_rebuild: start.nexus_rebuild.clone(),
        rebuild_requested: start.rebuild_requested,
        orchestration_token_sha256: start.orchestration_token_sha256.clone(),
        run_nonce: start.nonce.clone(),
        completed_unix_nanos: SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        toolchain,
        installed_path: String::from(TLA_TOOLCHAIN_INSTALLED_PATH),
        installed_bytes: TLA_TOOLCHAIN_JAR.bytes,
        installed_sha256: String::from(TLA_TOOLCHAIN_JAR.sha256),
        reported_version: String::from(TLA_TOOLCHAIN_VERSION_LINE),
    })
}

fn validate_formal_verifier_receipt(
    receipt: &FormalVerifierReceipt,
    start: &StartRecord,
    start_record_sha256: &str,
) -> Result<()> {
    validate_toolchain_receipt(&receipt.toolchain)?;
    if receipt.schema != FORMAL_VERIFIER_SCHEMA
        || receipt.start_record_sha256 != start_record_sha256
        || receipt.revision != start.revision
        || receipt.source_sha256 != start.source_sha256
        || receipt.worktree_dirty != start.worktree_dirty
        || receipt.invocation != start.invocation
        || receipt.nexus_rebuild != start.nexus_rebuild
        || receipt.rebuild_requested != start.rebuild_requested
        || receipt.orchestration_token_sha256 != start.orchestration_token_sha256
        || receipt.run_nonce != start.nonce
        || receipt.completed_unix_nanos < start.started_unix_nanos
        || receipt.installed_path != TLA_TOOLCHAIN_INSTALLED_PATH
        || receipt.installed_bytes != TLA_TOOLCHAIN_JAR.bytes
        || receipt.installed_sha256 != TLA_TOOLCHAIN_JAR.sha256
        || receipt.reported_version != TLA_TOOLCHAIN_VERSION_LINE
    {
        return Err(
            "formal verifier receipt does not bind the verification run and pinned runtime".into(),
        );
    }
    Ok(())
}

fn read_formal_verifier_receipt(
    base: &Path,
    start: &StartRecord,
    start_record_sha256: &str,
) -> Result<(StableRead, FormalVerifierReceipt)> {
    let file = read_regular_file_stable(
        &base.join(FORMAL_VERIFIER_RECEIPT),
        "formal verifier runtime receipt",
    )?;
    let receipt: FormalVerifierReceipt = serde_json::from_slice(&file.bytes)?;
    validate_formal_verifier_receipt(&receipt, start, start_record_sha256)?;
    Ok((file, receipt))
}

fn formal_verifier_binding(
    file: &StableRead,
    receipt: &FormalVerifierReceipt,
) -> Result<FormalVerifierBinding> {
    Ok(FormalVerifierBinding {
        toolchain: receipt.toolchain.clone(),
        installed_path: receipt.installed_path.clone(),
        runtime_receipt: Artifact {
            path: String::from(FORMAL_VERIFIER_RECEIPT),
            bytes: u64::try_from(file.bytes.len())?,
            sha256: sha256(&file.bytes),
        },
    })
}

fn validate_formal_verifier_binding(binding: &FormalVerifierBinding) -> Result<()> {
    validate_toolchain_receipt(&binding.toolchain)?;
    if binding.installed_path != TLA_TOOLCHAIN_INSTALLED_PATH
        || binding.runtime_receipt.path != FORMAL_VERIFIER_RECEIPT
        || binding.runtime_receipt.bytes == 0
        || !is_sha256(&binding.runtime_receipt.sha256)
    {
        return Err("formal verifier manifest binding differs from the pinned contract".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Boundaries {
    bounded_graph: bool,
    single_cpu: bool,
    cross_fd_total_order_claimed: bool,
    identity_preserving_stage5b_composition: bool,
    runtime_filesystem: bool,
    runtime_network: bool,
    linux_io_composition: bool,
    linux_io_composition_domains: u64,
    linux_io_composition_effects: u64,
    linux_io_composition_causal_nodes: u64,
    linux_io_composition_causal_edges: u64,
    linux_io_composition_credit_classes: u64,
    linux_io_composition_credit_units: u64,
    linux_io_composition_same_boot_kernel_adapters: bool,
    retained_workload_identity_preserved: bool,
    retained_effects_in_composition_cohort: bool,
    registry_multi_domain_binding: bool,
    stage5b_relation: &'static str,
    stage5b_same_boot: bool,
    real_dma_primary: bool,
    same_boot_runtime_fs_identity_observed: bool,
    same_boot_runtime_fs_effects: u64,
    same_boot_runtime_fs_registry_domains: u64,
    same_boot_runtime_fs_real_dma_observed: bool,
    same_boot_runtime_fs_precommit_revoke_wins_observed: bool,
    same_boot_runtime_fs_all_fault_paths_observed: bool,
    same_boot_runtime_fs_irq_observed: bool,
    same_boot_runtime_fs_smp_vcpus: u64,
    same_boot_runtime_fs_real_user_service_crash_observed: bool,
    stage7b_concurrency_boundary: &'static str,
    stage7b_concurrency_races_checked: u64,
    stage7b_fault_cells_checked: u64,
    stage7b_scale_points_checked: u64,
    stage7b_performance_cases_observed: u64,
    stage7b_performance_claim: &'static str,
    stage7b_prior_art_rows_checked: u64,
    stage7b_prior_art_full_text: u64,
    stage7b_prior_art_metadata_only: u64,
    stage7b_contribution_verdict: &'static str,
    novelty_established: bool,
    first_established: bool,
    proved_established: bool,
    smp_checked: bool,
    hardware_cycles_observed: bool,
    lock_freedom_established: bool,
    durable_external_effects_covered: bool,
    linux_breadth_established: bool,
    full_production_adapter_equivalence_established: bool,
}

impl Boundaries {
    fn current(prior_art: &crate::stage7b_prior_art::Summary) -> Result<Self> {
        let stage7b_prior_art_rows_checked = u64::try_from(prior_art.rows)?;
        let stage7b_prior_art_full_text = u64::try_from(prior_art.full_text)?;
        let stage7b_prior_art_metadata_only = u64::try_from(prior_art.metadata_only)?;
        if prior_art.source_cards != prior_art.rows
            || prior_art.default_verdict != "narrow"
            || prior_art.support_bounded_allowed
        {
            return Err("Stage 7B prior-art summary is outside the manifest boundary".into());
        }
        Ok(Self {
            bounded_graph: true,
            single_cpu: true,
            cross_fd_total_order_claimed: false,
            identity_preserving_stage5b_composition: false,
            runtime_filesystem: true,
            runtime_network: true,
            linux_io_composition: true,
            linux_io_composition_domains: 7,
            linux_io_composition_effects: 9,
            linux_io_composition_causal_nodes: 10,
            linux_io_composition_causal_edges: 9,
            linux_io_composition_credit_classes: 8,
            linux_io_composition_credit_units: 9,
            linux_io_composition_same_boot_kernel_adapters: true,
            retained_workload_identity_preserved: false,
            retained_effects_in_composition_cohort: false,
            registry_multi_domain_binding: false,
            stage5b_relation: "component_consistency",
            stage5b_same_boot: false,
            real_dma_primary: false,
            same_boot_runtime_fs_identity_observed: true,
            same_boot_runtime_fs_effects: 6,
            same_boot_runtime_fs_registry_domains: 3,
            same_boot_runtime_fs_real_dma_observed: true,
            same_boot_runtime_fs_precommit_revoke_wins_observed: true,
            same_boot_runtime_fs_all_fault_paths_observed: false,
            same_boot_runtime_fs_irq_observed: false,
            same_boot_runtime_fs_smp_vcpus: 1,
            same_boot_runtime_fs_real_user_service_crash_observed: true,
            stage7b_concurrency_boundary: "production transition source under a Loom-modeled outer mutex",
            stage7b_concurrency_races_checked: 14,
            stage7b_fault_cells_checked: 20,
            stage7b_scale_points_checked: 14,
            stage7b_performance_cases_observed: 29,
            stage7b_performance_claim: "Observed",
            stage7b_prior_art_rows_checked,
            stage7b_prior_art_full_text,
            stage7b_prior_art_metadata_only,
            stage7b_contribution_verdict: "narrow",
            novelty_established: false,
            first_established: false,
            proved_established: false,
            smp_checked: false,
            hardware_cycles_observed: false,
            lock_freedom_established: false,
            durable_external_effects_covered: false,
            linux_breadth_established: false,
            full_production_adapter_equivalence_established: false,
        })
    }
}

#[derive(Serialize)]
struct Stage {
    id: &'static str,
    evidence: Vec<String>,
}

fn manifest_stages(specs: &[&str]) -> Vec<Stage> {
    let mut formal_evidence: Vec<_> = specs
        .iter()
        .map(|spec| format!("target/verification/{spec}-tlc.log"))
        .collect();
    formal_evidence.push(String::from(FORMAL_VERIFIER_RECEIPT));
    formal_evidence.extend(
        toolchain_files(&expected_toolchain_receipt())
            .into_iter()
            .map(|file| file.path.clone()),
    );
    vec![
        Stage {
            id: "reference-model",
            evidence: vec![String::from("cargo test/clippy/canonical trace")],
        },
        Stage {
            id: "formal-specifications",
            evidence: formal_evidence,
        },
        Stage {
            id: "ostd-five-domain-composition",
            evidence: vec![
                String::from("kernel/nexus-ostd/artifacts/serial.log"),
                String::from("kernel/nexus-ostd/artifacts/task-entry-debugcon.log"),
                String::from("kernel/nexus-ostd/artifacts/task-entry-debugcon-oracle.log"),
            ],
        },
        Stage {
            id: "ostd-runtime-filesystem",
            evidence: vec![String::from("kernel/nexus-ostd/artifacts/serial.log")],
        },
        Stage {
            id: "ostd-runtime-filesystem-same-boot-device",
            evidence: vec![
                String::from("kernel/nexus-ostd/artifacts/runtime-fs-same-boot/serial.log"),
                String::from("kernel/nexus-ostd/artifacts/runtime-fs-same-boot/qemu-debug.log"),
                String::from(
                    "kernel/nexus-ostd/artifacts/runtime-fs-same-boot/task-entry-debugcon.log",
                ),
                String::from(
                    "kernel/nexus-ostd/artifacts/runtime-fs-same-boot/task-entry-debugcon-oracle.log",
                ),
                String::from("kernel/nexus-ostd/artifacts/runtime-fs-same-boot/oracle.log"),
            ],
        },
        Stage {
            id: "ostd-runtime-filesystem-precommit-revoke-wins",
            evidence: vec![
                String::from(
                    "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-precommit/serial.log",
                ),
                String::from(
                    "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-precommit/qemu-debug.log",
                ),
                String::from(
                    "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-precommit/task-entry-debugcon.log",
                ),
                String::from(
                    "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-precommit/task-entry-debugcon-oracle.log",
                ),
                String::from(
                    "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-precommit/oracle.log",
                ),
            ],
        },
        Stage {
            id: "ostd-runtime-network",
            evidence: vec![
                String::from("kernel/nexus-ostd/artifacts/serial.log"),
                String::from("target/verification/runtime-net-oracle.log"),
            ],
        },
        Stage {
            id: "ostd-seven-domain-linux-io-composition",
            evidence: vec![
                String::from("kernel/nexus-ostd/artifacts/serial.log"),
                String::from("target/verification/linux-io-composition-oracle.log"),
            ],
        },
        Stage {
            id: "mediated-virtio",
            evidence: vec![
                String::from("experiments/ostd-virtio-cser-spike/artifacts/kernel.log"),
                String::from("experiments/ostd-virtio-cser-spike/artifacts/qemu-debug.log"),
                String::from("experiments/ostd-virtio-cser-spike/artifacts/oracle.log"),
            ],
        },
        Stage {
            id: "system-composition",
            evidence: vec![String::from(
                "target/verification/system-composition-oracle.log",
            )],
        },
        Stage {
            id: "runtime-filesystem-composition",
            evidence: vec![String::from(
                "target/verification/runtime-fs-composition-oracle.log",
            )],
        },
        Stage {
            id: "implementation-source-concurrency",
            evidence: vec![
                String::from("target/verification/stage7b/concurrency.log"),
                String::from("target/verification/stage7b/concurrency.json"),
                String::from("target/verification/stage7b/concurrency-oracle.log"),
            ],
        },
        Stage {
            id: "fault-matrix",
            evidence: vec![String::from(
                "target/verification/stage7b/fault-matrix.jsonl",
            )],
        },
        Stage {
            id: "scale-structure",
            evidence: vec![String::from("target/verification/stage7b/scale.jsonl")],
        },
        Stage {
            id: "performance-observation",
            evidence: vec![
                String::from("kernel/nexus-ostd/artifacts/stage7b-evaluation.log"),
                String::from("kernel/nexus-ostd/artifacts/stage7b-runtime-metadata.env"),
                String::from("target/verification/stage7b/performance.json"),
                String::from("target/verification/stage7b/oracle.log"),
            ],
        },
        Stage {
            id: "primary-source-prior-art",
            evidence: vec![
                String::from("target/verification/stage7b/prior-art.json"),
                String::from("target/verification/stage7b/prior-art-oracle.log"),
            ],
        },
        Stage {
            id: "contribution-decision",
            evidence: vec![
                String::from("target/verification/stage7b/contribution.json"),
                String::from("target/verification/stage7b/contribution-oracle.log"),
            ],
        },
    ]
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MetadataStamp {
    device: u64,
    inode: u64,
    mode: u32,
    length: u64,
    modified: SystemTime,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Debug)]
struct StableRead {
    bytes: Vec<u8>,
    metadata: MetadataStamp,
}

pub(crate) fn begin(root: &Path, specs: &[&str]) -> Result<PathBuf> {
    let source = source_snapshot(root)?;
    let environment = verification_environment()?;
    let started_unix_nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let process_id = std::process::id();
    let token = verification_token()?;
    let orchestration_token_sha256 = sha256(token.as_bytes());
    let nonce = start_nonce(
        &source,
        &environment,
        &orchestration_token_sha256,
        process_id,
        started_unix_nanos,
    );
    let rebuild_requested = rebuild_requested(&environment);
    let record = StartRecord {
        schema: String::from(START_SCHEMA),
        revision: source.revision,
        source_sha256: source.source_sha256,
        worktree_dirty: source.worktree_dirty,
        invocation: environment.invocation,
        nexus_rebuild: environment.nexus_rebuild,
        rebuild_requested,
        orchestration_token_sha256,
        nonce,
        process_id,
        started_unix_nanos,
    };
    let path = root.join(SENTINEL);
    let parent = path
        .parent()
        .ok_or("verification start path has no parent")?;
    fs::create_dir_all(parent)?;
    clear_expected_evidence(root, specs)?;
    let temporary = format!(".stage7a-verify-start.{}.tmp", record.nonce);
    atomic_json(parent, &path, &temporary, &record)?;
    println!(
        "verification start: PASS revision={} dirty={} rebuild={} nonce={}",
        record.revision, record.worktree_dirty, record.rebuild_requested, record.nonce
    );
    Ok(path)
}

pub(crate) fn mark_model_spec_complete(root: &Path, specs: &[&str]) -> Result<PathBuf> {
    let sentinel = root.join(SENTINEL);
    let start_file =
        read_regular_file_stable(&sentinel, "verification start record").map_err(|error| {
            format!(
                "verification freshness record {}: {error}",
                sentinel.display()
            )
        })?;
    let start: StartRecord = serde_json::from_slice(&start_file.bytes)?;
    let start_record_sha256 = sha256(&start_file.bytes);
    let current_source = source_snapshot(root)?;
    let current_environment = verification_environment()?;
    validate_start_record(&start, &current_source, Some(&current_environment))?;

    let artifacts = validate_artifacts(
        root,
        &model_spec_artifacts(specs),
        start_file.metadata.modified,
    )?;
    let verifier = capture_formal_verifier(root, &start, &start_record_sha256)?;
    remove_evidence_file(root, FORMAL_VERIFIER_RECEIPT)?;
    remove_evidence_file(root, MODEL_SPEC_RECEIPT)?;
    remove_evidence_file(root, COMPLETION_RECEIPT)?;
    remove_evidence_file(root, OUTPUT)?;
    let verifier_path = root.join(FORMAL_VERIFIER_RECEIPT);
    let verifier_parent = verifier_path
        .parent()
        .ok_or("formal verifier receipt path has no parent")?;
    let verifier_temporary = format!(".formal-verifier.{}.tmp", verifier.run_nonce);
    atomic_json(
        verifier_parent,
        &verifier_path,
        &verifier_temporary,
        &verifier,
    )?;
    let (verifier_file, verifier) =
        read_formal_verifier_receipt(root, &start, &start_record_sha256)?;
    validate_toolchain_files(root, &verifier.toolchain)?;
    let verifier_sha256 = sha256(&verifier_file.bytes);
    let receipt = gate_receipt(
        MODEL_SPEC_SCHEMA,
        &start,
        ["reference-model", "formal-specifications"],
        Some(verifier_sha256),
        artifacts,
    )?;

    let path = root.join(MODEL_SPEC_RECEIPT);
    let parent = path
        .parent()
        .ok_or("model/spec receipt path has no parent")?;
    let temporary = format!(".stage7a-model-spec.{}.tmp", receipt.run_nonce);
    atomic_json(parent, &path, &temporary, &receipt)?;
    println!(
        "formal verifier receipt: PASS path={} jar_sha256={} version={}",
        verifier_path.display(),
        verifier.installed_sha256,
        verifier.reported_version
    );
    println!(
        "verification model/spec receipt: PASS path={} artifacts={} nonce={}",
        path.display(),
        receipt.artifacts.len(),
        receipt.run_nonce
    );
    Ok(path)
}

pub(crate) fn complete(root: &Path, specs: &[&str]) -> Result<PathBuf> {
    let sentinel = root.join(SENTINEL);
    let start_file =
        read_regular_file_stable(&sentinel, "verification start record").map_err(|error| {
            format!(
                "verification freshness record {}: {error}",
                sentinel.display()
            )
        })?;
    let start: StartRecord = serde_json::from_slice(&start_file.bytes)?;
    let start_record_sha256 = sha256(&start_file.bytes);
    let current_source = source_snapshot(root)?;
    let current_environment = verification_environment()?;
    validate_start_record(&start, &current_source, Some(&current_environment))?;
    validate_completion_token(&start)?;

    let (verifier_file, verifier) =
        read_formal_verifier_receipt(root, &start, &start_record_sha256)
            .map_err(|error| format!("required formal verifier receipt: {error}"))?;
    validate_toolchain_files(root, &verifier.toolchain)?;
    let verifier_sha256 = sha256(&verifier_file.bytes);

    let model_path = root.join(MODEL_SPEC_RECEIPT);
    let model_file = read_regular_file_stable(&model_path, "model/spec completion receipt")
        .map_err(|error| format!("required model/spec completion receipt: {error}"))?;
    let model_receipt: GateReceipt = serde_json::from_slice(&model_file.bytes)?;
    let model_artifacts = validate_artifacts(
        root,
        &model_spec_artifacts(specs),
        start_file.metadata.modified,
    )?;
    validate_gate_receipt(
        &model_receipt,
        MODEL_SPEC_SCHEMA,
        &start,
        &["reference-model", "formal-specifications"],
        Some(&verifier_sha256),
        &model_artifacts,
    )?;
    let model_sha256 = sha256(&model_file.bytes);

    let artifacts = validate_artifacts(
        root,
        &required_artifacts(specs),
        start_file.metadata.modified,
    )?;
    let receipt = gate_receipt(
        COMPLETE_SCHEMA,
        &start,
        COMPLETE_STAGES,
        Some(model_sha256),
        artifacts,
    )?;

    remove_evidence_file(root, OUTPUT)?;
    let path = root.join(COMPLETION_RECEIPT);
    let parent = path
        .parent()
        .ok_or("verification completion receipt path has no parent")?;
    let temporary = format!(".stage7a-verify-complete.{}.tmp", receipt.run_nonce);
    atomic_json(parent, &path, &temporary, &receipt)?;
    println!(
        "verification completion receipt: PASS path={} artifacts={} nonce={}",
        path.display(),
        receipt.artifacts.len(),
        receipt.run_nonce
    );
    Ok(path)
}

pub(crate) fn write(root: &Path, specs: &[&str]) -> Result<PathBuf> {
    let token = verification_token()?;
    let environment = verification_environment()?;
    write_authorized(root, specs, &token, &environment)
}

fn write_authorized(
    root: &Path,
    specs: &[&str],
    token: &str,
    environment: &VerificationEnvironment,
) -> Result<PathBuf> {
    let sentinel = root.join(SENTINEL);
    let start_file =
        read_regular_file_stable(&sentinel, "verification start record").map_err(|error| {
            format!(
                "verification freshness record {}: {error}",
                sentinel.display()
            )
        })?;
    let start: StartRecord = serde_json::from_slice(&start_file.bytes)?;
    let start_record_sha256 = sha256(&start_file.bytes);
    let current_source = source_snapshot(root)?;
    validate_start_record(&start, &current_source, Some(environment))?;
    validate_completion_token_value(&start, token)?;

    let (verifier_file, verifier) =
        read_formal_verifier_receipt(root, &start, &start_record_sha256)
            .map_err(|error| format!("required formal verifier receipt: {error}"))?;
    validate_toolchain_files(root, &verifier.toolchain)?;
    let verifier_sha256 = sha256(&verifier_file.bytes);

    let model_path = root.join(MODEL_SPEC_RECEIPT);
    let model_file = read_regular_file_stable(&model_path, "model/spec completion receipt")
        .map_err(|error| format!("required model/spec completion receipt: {error}"))?;
    let model_receipt: GateReceipt = serde_json::from_slice(&model_file.bytes)?;
    let model_artifacts = validate_artifacts(
        root,
        &model_spec_artifacts(specs),
        start_file.metadata.modified,
    )?;
    validate_gate_receipt(
        &model_receipt,
        MODEL_SPEC_SCHEMA,
        &start,
        &["reference-model", "formal-specifications"],
        Some(&verifier_sha256),
        &model_artifacts,
    )?;
    let model_sha256 = sha256(&model_file.bytes);

    let completion_path = root.join(COMPLETION_RECEIPT);
    let completion_file =
        read_regular_file_stable(&completion_path, "verification completion receipt")
            .map_err(|error| format!("required verification completion receipt: {error}"))?;
    let completion: GateReceipt = serde_json::from_slice(&completion_file.bytes)?;
    let artifacts = validate_artifacts(
        root,
        &required_artifacts(specs),
        start_file.metadata.modified,
    )?;
    validate_gate_receipt(
        &completion,
        COMPLETE_SCHEMA,
        &start,
        &COMPLETE_STAGES,
        Some(&model_sha256),
        &artifacts,
    )?;
    let completion_receipt_sha256 = sha256(&completion_file.bytes);

    let generated_unix_seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let stages = manifest_stages(specs);
    let formal_verifier = formal_verifier_binding(&verifier_file, &verifier)?;
    let prior_art = crate::stage7b_prior_art::receipt_summary(root)
        .map_err(|error| format!("Stage 7B prior-art manifest binding: {error}"))?;
    let manifest = Manifest {
        schema: SCHEMA,
        status: "passed",
        command: start.invocation,
        revision: start.revision,
        source_sha256: start.source_sha256,
        worktree_dirty: start.worktree_dirty,
        nexus_rebuild: start.nexus_rebuild,
        rebuild_requested: start.rebuild_requested,
        orchestration_token_sha256: start.orchestration_token_sha256,
        run_nonce: start.nonce,
        completion_receipt_sha256,
        started_unix_nanos: start.started_unix_nanos,
        generated_unix_seconds,
        formal_verifier,
        boundaries: Boundaries::current(&prior_art)?,
        specifications: specs.iter().map(|spec| String::from(*spec)).collect(),
        stages,
        artifacts,
    };

    let output = root.join(OUTPUT);
    let parent = output.parent().ok_or("manifest output has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = format!(".manifest.{}.tmp", manifest.run_nonce);
    atomic_json(parent, &output, &temporary, &manifest)?;
    println!(
        "verification manifest: PASS path={} artifacts={} schema={SCHEMA}",
        output.display(),
        manifest.artifacts.len()
    );
    Ok(output)
}

fn verification_environment() -> Result<VerificationEnvironment> {
    optional_verification_environment()?
        .ok_or_else(|| "NEXUS_VERIFY_INVOCATION is required for verification evidence begin".into())
}

fn optional_verification_environment() -> Result<Option<VerificationEnvironment>> {
    let invocation = match std::env::var("NEXUS_VERIFY_INVOCATION") {
        Ok(value) if value.trim().is_empty() => return Ok(None),
        Ok(value) => value,
        Err(VarError::NotPresent) => return Ok(None),
        Err(VarError::NotUnicode(_)) => {
            return Err("NEXUS_VERIFY_INVOCATION must contain valid Unicode".into());
        }
    };
    let nexus_rebuild = match std::env::var("NEXUS_REBUILD") {
        Ok(value) => Some(value),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => {
            return Err("NEXUS_REBUILD must contain valid Unicode".into());
        }
    };
    Ok(Some(VerificationEnvironment {
        invocation,
        nexus_rebuild,
    }))
}

fn verification_token() -> Result<String> {
    let token = match std::env::var("NEXUS_VERIFY_TOKEN") {
        Ok(value) => value,
        Err(VarError::NotPresent) => {
            return Err("NEXUS_VERIFY_TOKEN is required for verification sealing".into());
        }
        Err(VarError::NotUnicode(_)) => {
            return Err("NEXUS_VERIFY_TOKEN must contain valid Unicode".into());
        }
    };
    if !is_sha256(&token) {
        return Err("NEXUS_VERIFY_TOKEN must be 64 lowercase hexadecimal characters".into());
    }
    Ok(token)
}

fn validate_completion_token(start: &StartRecord) -> Result<()> {
    let token = verification_token()?;
    validate_completion_token_value(start, &token)
}

fn validate_completion_token_value(start: &StartRecord, token: &str) -> Result<()> {
    if !is_sha256(token) {
        return Err("verification orchestration token is malformed".into());
    }
    if sha256(token.as_bytes()) != start.orchestration_token_sha256 {
        return Err("NEXUS_VERIFY_TOKEN does not authorize this verification run".into());
    }
    Ok(())
}

fn rebuild_requested(environment: &VerificationEnvironment) -> bool {
    environment.nexus_rebuild.as_deref() == Some("1")
}

fn start_nonce(
    source: &SourceSnapshot,
    environment: &VerificationEnvironment,
    orchestration_token_sha256: &str,
    process_id: u32,
    started_unix_nanos: u128,
) -> String {
    let mut digest = Sha256::new();
    digest_field(&mut digest, START_SCHEMA.as_bytes());
    digest_field(&mut digest, source.revision.as_bytes());
    digest_field(&mut digest, source.source_sha256.as_bytes());
    digest.update([u8::from(source.worktree_dirty)]);
    digest_field(&mut digest, environment.invocation.as_bytes());
    match &environment.nexus_rebuild {
        Some(value) => {
            digest.update([1]);
            digest_field(&mut digest, value.as_bytes());
        }
        None => digest.update([0]),
    }
    digest_field(&mut digest, orchestration_token_sha256.as_bytes());
    digest.update(process_id.to_le_bytes());
    digest.update(started_unix_nanos.to_le_bytes());
    format!("{:x}", digest.finalize())
}

fn validate_start_record(
    start: &StartRecord,
    current_source: &SourceSnapshot,
    current_environment: Option<&VerificationEnvironment>,
) -> Result<()> {
    if start.schema != START_SCHEMA {
        return Err(format!("unsupported verification start schema: {}", start.schema).into());
    }
    if start.revision.is_empty()
        || start.invocation.trim().is_empty()
        || start.process_id == 0
        || start.started_unix_nanos == 0
        || !is_sha256(&start.source_sha256)
        || !is_sha256(&start.orchestration_token_sha256)
        || !is_sha256(&start.nonce)
    {
        return Err("verification start record has malformed bound fields".into());
    }
    if start.started_unix_nanos > SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() {
        return Err("verification start record timestamp is in the future".into());
    }
    let recorded_source = SourceSnapshot {
        revision: start.revision.clone(),
        source_sha256: start.source_sha256.clone(),
        worktree_dirty: start.worktree_dirty,
    };
    let recorded_environment = VerificationEnvironment {
        invocation: start.invocation.clone(),
        nexus_rebuild: start.nexus_rebuild.clone(),
    };
    if start.rebuild_requested != rebuild_requested(&recorded_environment) {
        return Err("verification start record has inconsistent NEXUS_REBUILD fields".into());
    }
    let expected_nonce = start_nonce(
        &recorded_source,
        &recorded_environment,
        &start.orchestration_token_sha256,
        start.process_id,
        start.started_unix_nanos,
    );
    if start.nonce != expected_nonce {
        return Err("verification start record nonce does not bind its recorded fields".into());
    }
    if &recorded_source != current_source {
        return Err(format!(
            "source changed after verification began: revision {}->{}, fingerprint {}->{}, dirty {}->{}",
            recorded_source.revision,
            current_source.revision,
            recorded_source.source_sha256,
            current_source.source_sha256,
            recorded_source.worktree_dirty,
            current_source.worktree_dirty
        )
        .into());
    }
    if let Some(current_environment) = current_environment
        && &recorded_environment != current_environment
    {
        return Err(format!(
            "verification environment changed after verification began: invocation {:?}->{:?}, NEXUS_REBUILD {:?}->{:?}",
            recorded_environment.invocation,
            current_environment.invocation,
            recorded_environment.nexus_rebuild,
            current_environment.nexus_rebuild
        )
        .into());
    }
    Ok(())
}

fn gate_receipt<I>(
    schema: &str,
    start: &StartRecord,
    stages: I,
    prerequisite_sha256: Option<String>,
    artifacts: Vec<Artifact>,
) -> Result<GateReceipt>
where
    I: IntoIterator<Item = &'static str>,
{
    Ok(GateReceipt {
        schema: String::from(schema),
        revision: start.revision.clone(),
        source_sha256: start.source_sha256.clone(),
        worktree_dirty: start.worktree_dirty,
        invocation: start.invocation.clone(),
        nexus_rebuild: start.nexus_rebuild.clone(),
        rebuild_requested: start.rebuild_requested,
        orchestration_token_sha256: start.orchestration_token_sha256.clone(),
        run_nonce: start.nonce.clone(),
        completed_unix_nanos: SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        stages: stages.into_iter().map(String::from).collect(),
        prerequisite_sha256,
        artifacts,
    })
}

fn validate_gate_receipt(
    receipt: &GateReceipt,
    schema: &str,
    start: &StartRecord,
    stages: &[&str],
    prerequisite_sha256: Option<&str>,
    artifacts: &[Artifact],
) -> Result<()> {
    if receipt.schema != schema {
        return Err(format!(
            "unsupported verification gate receipt schema: {}",
            receipt.schema
        )
        .into());
    }
    if receipt.revision != start.revision
        || receipt.source_sha256 != start.source_sha256
        || receipt.worktree_dirty != start.worktree_dirty
        || receipt.invocation != start.invocation
        || receipt.nexus_rebuild != start.nexus_rebuild
        || receipt.rebuild_requested != start.rebuild_requested
        || receipt.orchestration_token_sha256 != start.orchestration_token_sha256
        || receipt.run_nonce != start.nonce
    {
        return Err("verification gate receipt does not bind the active start record".into());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    if receipt.completed_unix_nanos < start.started_unix_nanos || receipt.completed_unix_nanos > now
    {
        return Err("verification gate receipt has an invalid completion timestamp".into());
    }
    let expected_stages: Vec<_> = stages.iter().map(|stage| String::from(*stage)).collect();
    if receipt.stages != expected_stages {
        return Err("verification gate receipt has an unexpected stage set".into());
    }
    if receipt.prerequisite_sha256.as_deref() != prerequisite_sha256 {
        return Err("verification gate receipt prerequisite does not match".into());
    }
    if receipt
        .prerequisite_sha256
        .as_deref()
        .is_some_and(|digest| !is_sha256(digest))
    {
        return Err("verification gate receipt prerequisite is not a SHA-256 digest".into());
    }
    if receipt.artifacts != artifacts {
        return Err(
            "verification artifacts changed after their completion receipt was issued".into(),
        );
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn model_spec_artifacts(specs: &[&str]) -> Vec<(String, Option<&'static str>)> {
    let mut required = Vec::with_capacity(specs.len() * 2);
    for spec in specs {
        required.push((
            format!("target/verification/{spec}-pluscal.log"),
            Some("Translation completed."),
        ));
        required.push((
            format!("target/verification/{spec}-tlc.log"),
            Some("Model checking completed. No error has been found."),
        ));
    }
    required
}

fn system_artifacts() -> Vec<(String, Option<&'static str>)> {
    vec![
        (
            String::from("kernel/nexus-ostd/artifacts/serial.log"),
            Some("COMPOSITION_SLICE PASS"),
        ),
        (
            String::from("kernel/nexus-ostd/artifacts/task-entry-debugcon.log"),
            None,
        ),
        (
            String::from("kernel/nexus-ostd/artifacts/task-entry-debugcon-oracle.log"),
            Some(ENTRY_DEBUGCON_PASS),
        ),
        (
            String::from("kernel/nexus-ostd/artifacts/runtime-fs-same-boot/serial.log"),
            Some(
                "LINUX_FS_SAME_BOOT PASS same_boot=true identity_preserving=true real_dma=true polling=true irq=false smp=1",
            ),
        ),
        (
            String::from("kernel/nexus-ostd/artifacts/runtime-fs-same-boot/qemu-debug.log"),
            Some("vtd_inv_desc_iotlb_global"),
        ),
        (
            String::from(
                "kernel/nexus-ostd/artifacts/runtime-fs-same-boot/task-entry-debugcon.log",
            ),
            None,
        ),
        (
            String::from(
                "kernel/nexus-ostd/artifacts/runtime-fs-same-boot/task-entry-debugcon-oracle.log",
            ),
            Some(ENTRY_DEBUGCON_PASS),
        ),
        (
            String::from("kernel/nexus-ostd/artifacts/runtime-fs-same-boot/oracle.log"),
            Some(
                "runtime filesystem same-boot serial/debug assertions: PASS real_user_service_crash=true fsd_task_key=current-task-bound+951:1->951:2 replacement_construction=post-crash",
            ),
        ),
        (
            String::from("kernel/nexus-ostd/artifacts/runtime-fs-same-boot-precommit/serial.log"),
            Some("LINUX_FS_SAME_BOOT_PRECOMMIT PASS"),
        ),
        (
            String::from(
                "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-precommit/qemu-debug.log",
            ),
            Some("vtd_inv_desc_iotlb_global"),
        ),
        (
            String::from(
                "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-precommit/task-entry-debugcon.log",
            ),
            None,
        ),
        (
            String::from(
                "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-precommit/task-entry-debugcon-oracle.log",
            ),
            Some(ENTRY_DEBUGCON_PASS),
        ),
        (
            String::from("kernel/nexus-ostd/artifacts/runtime-fs-same-boot-precommit/oracle.log"),
            Some(
                "runtime filesystem same-boot precommit serial/debug assertions: PASS real_user_service_crash=true fsd_task_key=current-task-bound+951:1->951:2 replacement_construction=post-crash",
            ),
        ),
        (
            String::from("experiments/ostd-virtio-cser-spike/artifacts/kernel.log"),
            Some("VIRTIO_CSER PASS"),
        ),
        (
            String::from("experiments/ostd-virtio-cser-spike/artifacts/qemu-debug.log"),
            Some("vtd_inv_desc_iotlb_global"),
        ),
        (
            String::from("experiments/ostd-virtio-cser-spike/artifacts/oracle.log"),
            Some("qemu_request_identity=bound"),
        ),
        (
            String::from("target/verification/system-composition-oracle.log"),
            Some("missing_iotlb_trace=rejected"),
        ),
        (
            String::from("target/verification/runtime-fs-composition-oracle.log"),
            Some("RUNTIME_FS_COMPOSITION PASS"),
        ),
        (
            String::from("target/verification/runtime-net-oracle.log"),
            Some("RUNTIME_NET_ORACLE PASS"),
        ),
        (
            String::from("target/verification/linux-io-composition-oracle.log"),
            Some("LINUX_IO_COMPOSITION_EVIDENCE PASS"),
        ),
        (
            String::from("kernel/nexus-ostd/artifacts/stage7b-evaluation.log"),
            Some("STAGE7B_EVALUATION PASS faults=20 scale_points=14 performance_cases=29"),
        ),
        (
            String::from("kernel/nexus-ostd/artifacts/stage7b-runtime-metadata.env"),
            Some("schema=nexus.stage7b.runtime-metadata.v1"),
        ),
        (
            String::from("kernel/nexus-ostd/artifacts/stage7b-qemu-debug.log"),
            Some("Finished"),
        ),
        (
            String::from("target/verification/stage7b/concurrency.log"),
            Some("STAGE7B_CONCURRENCY case=commit_vs_revoke_linearization status=PASS"),
        ),
        (
            String::from("target/verification/stage7b/concurrency.json"),
            Some("nexus.stage7b.concurrency.v1"),
        ),
        (
            String::from("target/verification/stage7b/concurrency-oracle.log"),
            Some("races=14"),
        ),
        (
            String::from("target/verification/stage7b/fault-matrix.jsonl"),
            Some("\"status\":\"Checked\""),
        ),
        (
            String::from("target/verification/stage7b/scale.jsonl"),
            Some("\"status\":\"Checked\""),
        ),
        (
            String::from("target/verification/stage7b/performance.json"),
            Some("nexus.stage7b.performance.v1"),
        ),
        (
            String::from("target/verification/stage7b/oracle.log"),
            Some("performance_claim=Observed"),
        ),
        (
            String::from("target/verification/stage7b/prior-art.json"),
            Some("nexus.stage7b.prior-art.receipt.v1"),
        ),
        (
            String::from("target/verification/stage7b/prior-art-oracle.log"),
            Some("support_bounded_allowed=false"),
        ),
        (
            String::from("target/verification/stage7b/contribution.json"),
            Some("nexus.stage7b.contribution-decision.v1"),
        ),
        (
            String::from("target/verification/stage7b/contribution-oracle.log"),
            Some("verdict=narrow"),
        ),
    ]
}

fn required_artifacts(specs: &[&str]) -> Vec<(String, Option<&'static str>)> {
    let mut required = model_spec_artifacts(specs);
    required.extend(system_artifacts());
    required
}

fn clear_expected_evidence(root: &Path, specs: &[&str]) -> Result<()> {
    bundle::clear_bundle(root)?;
    for relative in [
        String::from(SENTINEL),
        String::from(FORMAL_VERIFIER_RECEIPT),
        String::from(MODEL_SPEC_RECEIPT),
        String::from(COMPLETION_RECEIPT),
        String::from(OUTPUT),
    ]
    .into_iter()
    .chain(required_artifacts(specs).into_iter().map(|(path, _)| path))
    {
        remove_evidence_file(root, &relative)?;
    }
    Ok(())
}

fn remove_evidence_file(root: &Path, relative: &str) -> Result<()> {
    match fs::remove_file(root.join(relative)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove stale verification evidence {relative}: {error}").into()),
    }
}

fn source_snapshot(root: &Path) -> Result<SourceSnapshot> {
    let revision = git(root, &["rev-parse", "HEAD"])?;
    let status = git_output(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    let listing = git_output(
        root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?;
    let mut paths: Vec<_> = listing
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| PathBuf::from(OsString::from_vec(bytes.to_vec())))
        .collect();
    paths.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
    paths.dedup();
    let source_sha256 = fingerprint_paths(root, &paths)?;
    Ok(SourceSnapshot {
        revision,
        source_sha256,
        worktree_dirty: !status.is_empty(),
    })
}

fn fingerprint_paths(root: &Path, paths: &[PathBuf]) -> Result<String> {
    let mut digest = Sha256::new();
    for relative in paths {
        if relative.is_absolute() {
            return Err(format!("source path is not repository-relative: {relative:?}").into());
        }
        let path = root.join(relative);
        let relative_bytes = relative.as_os_str().as_bytes();
        digest_field(&mut digest, relative_bytes);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                digest.update([0]);
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() {
            digest.update([1]);
            let before = metadata_stamp(&metadata)?;
            let target = fs::read_link(&path)?;
            let after = metadata_stamp(&fs::symlink_metadata(&path)?)?;
            if before != after {
                return Err(
                    format!("source symlink changed while fingerprinting: {relative:?}").into(),
                );
            }
            digest.update(before.mode.to_le_bytes());
            digest_field(&mut digest, target.as_os_str().as_bytes());
        } else if metadata.is_file() {
            digest.update([2]);
            let read = read_regular_file_stable(&path, "source file")?;
            digest.update(read.metadata.mode.to_le_bytes());
            digest_field(&mut digest, &read.bytes);
        } else {
            return Err(
                format!("source path is neither a file nor a symlink: {relative:?}").into(),
            );
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn digest_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn atomic_json<T: Serialize>(parent: &Path, output: &Path, name: &str, value: &T) -> Result<()> {
    let temporary = parent.join(name);
    fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&temporary, output)?;
    Ok(())
}

fn validate_artifact(
    root: &Path,
    relative: &str,
    marker: Option<&str>,
    sentinel_time: SystemTime,
) -> Result<Artifact> {
    let path = root.join(relative);
    let read = read_regular_file_stable(&path, "verification artifact")
        .map_err(|error| format!("required verification artifact {relative}: {error}"))?;
    if read.bytes.is_empty() {
        return Err(format!("verification artifact is empty or not a file: {relative}").into());
    }
    if read.metadata.modified <= sentinel_time {
        return Err(format!("verification artifact predates this run: {relative}").into());
    }

    if let Some(marker) = marker {
        let text = String::from_utf8_lossy(&read.bytes);
        if !text.contains(marker) {
            return Err(format!("verification artifact lacks {marker:?}: {relative}").into());
        }
        if relative.ends_with("-tlc.log")
            && !text.lines().any(|line| line == TLA_TOOLCHAIN_VERSION_LINE)
        {
            return Err(format!(
                "verification artifact lacks the pinned TLC version line: {relative}"
            )
            .into());
        }
        if relative.ends_with("-pluscal.log")
            && !text.lines().any(|line| line == PLUSCAL_VERSION_LINE)
        {
            return Err(format!(
                "verification artifact lacks the pinned PlusCal version line: {relative}"
            )
            .into());
        }
    }
    let byte_count = u64::try_from(read.bytes.len())?;
    let digest = Sha256::digest(&read.bytes);
    Ok(Artifact {
        path: String::from(relative),
        bytes: byte_count,
        sha256: format!("{digest:x}"),
    })
}

fn validate_artifacts(
    root: &Path,
    required: &[(String, Option<&'static str>)],
    sentinel_time: SystemTime,
) -> Result<Vec<Artifact>> {
    required
        .iter()
        .map(|(relative, marker)| validate_artifact(root, relative, *marker, sentinel_time))
        .collect()
}

fn read_regular_file_stable(path: &Path, label: &str) -> Result<StableRead> {
    read_regular_file_stable_with(path, label, |_| Ok(()))
}

fn read_regular_file_stable_with<F>(path: &Path, label: &str, after_open: F) -> Result<StableRead>
where
    F: FnOnce(&Path) -> Result<()>,
{
    let path_before = fs::symlink_metadata(path)?;
    if !path_before.is_file() {
        return Err(format!("{label} is not a regular file: {}", path.display()).into());
    }
    let path_before = metadata_stamp(&path_before)?;
    let mut file = fs::File::open(path)?;
    let descriptor_before = metadata_stamp(&file.metadata()?)?;
    if path_before != descriptor_before {
        return Err(format!("{label} changed while it was opened: {}", path.display()).into());
    }

    after_open(path)?;
    let mut bytes = Vec::with_capacity(usize::try_from(descriptor_before.length).unwrap_or(0));
    file.read_to_end(&mut bytes)?;

    let descriptor_after = metadata_stamp(&file.metadata()?)?;
    let path_after = metadata_stamp(&fs::symlink_metadata(path)?)?;
    if descriptor_before != descriptor_after || descriptor_before != path_after {
        return Err(format!("{label} changed while it was read: {}", path.display()).into());
    }
    if descriptor_before.length != u64::try_from(bytes.len())? {
        return Err(format!(
            "{label} read length disagrees with stable metadata: {}",
            path.display()
        )
        .into());
    }
    Ok(StableRead {
        bytes,
        metadata: descriptor_before,
    })
}

fn metadata_stamp(metadata: &fs::Metadata) -> Result<MetadataStamp> {
    Ok(MetadataStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        length: metadata.len(),
        modified: metadata.modified()?,
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git_output(root, args)?)?
        .trim()
        .to_owned())
}

fn git_output(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git").current_dir(root).args(args).output()?;
    if !output.status.success() {
        return Err(format!("git {:?} failed with {}", args, output.status).into());
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nexus-evidence-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("create fixture");
        path
    }

    fn copy_toolchain_fixture(root: &Path) {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let receipt = expected_toolchain_receipt();
        for file in toolchain_files(&receipt) {
            let destination = root.join(&file.path);
            fs::create_dir_all(destination.parent().expect("toolchain parent"))
                .expect("create toolchain parent");
            fs::copy(repository.join(&file.path), destination)
                .expect("copy pinned toolchain fixture");
        }
    }

    fn start_record(source: &SourceSnapshot, environment: &VerificationEnvironment) -> StartRecord {
        let process_id = 17;
        let started_unix_nanos = 1_234_567;
        let token = "f".repeat(64);
        let orchestration_token_sha256 = sha256(token.as_bytes());
        StartRecord {
            schema: String::from(START_SCHEMA),
            revision: source.revision.clone(),
            source_sha256: source.source_sha256.clone(),
            worktree_dirty: source.worktree_dirty,
            invocation: environment.invocation.clone(),
            nexus_rebuild: environment.nexus_rebuild.clone(),
            rebuild_requested: rebuild_requested(environment),
            nonce: start_nonce(
                source,
                environment,
                &orchestration_token_sha256,
                process_id,
                started_unix_nanos,
            ),
            orchestration_token_sha256,
            process_id,
            started_unix_nanos,
        }
    }

    fn formal_verifier_receipt(
        start: &StartRecord,
        start_record_sha256: String,
    ) -> FormalVerifierReceipt {
        let toolchain = expected_toolchain_receipt();
        FormalVerifierReceipt {
            schema: String::from(FORMAL_VERIFIER_SCHEMA),
            start_record_sha256,
            revision: start.revision.clone(),
            source_sha256: start.source_sha256.clone(),
            worktree_dirty: start.worktree_dirty,
            invocation: start.invocation.clone(),
            nexus_rebuild: start.nexus_rebuild.clone(),
            rebuild_requested: start.rebuild_requested,
            orchestration_token_sha256: start.orchestration_token_sha256.clone(),
            run_nonce: start.nonce.clone(),
            completed_unix_nanos: start.started_unix_nanos + 1,
            installed_path: String::from(TLA_TOOLCHAIN_INSTALLED_PATH),
            installed_bytes: toolchain.jar.bytes,
            installed_sha256: toolchain.jar.sha256.clone(),
            reported_version: String::from(TLA_TOOLCHAIN_VERSION_LINE),
            toolchain,
        }
    }

    fn write_required_evidence(root: &Path, specs: &[&str]) {
        for relative in [
            String::from(SENTINEL),
            String::from(FORMAL_VERIFIER_RECEIPT),
            String::from(MODEL_SPEC_RECEIPT),
            String::from(COMPLETION_RECEIPT),
            String::from(OUTPUT),
        ]
        .into_iter()
        .chain(required_artifacts(specs).into_iter().map(|(path, _)| path))
        {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().expect("evidence parent"))
                .expect("create evidence parent");
            fs::write(path, "old evidence\n").expect("write old evidence");
        }
    }

    #[test]
    fn manifest_boundaries_fix_linux_io_shape_and_non_identity_claims() {
        let prior_art = crate::stage7b_prior_art::Summary {
            rows: 16,
            source_cards: 16,
            full_text: 15,
            metadata_only: 1,
            default_verdict: String::from("narrow"),
            support_bounded_allowed: false,
        };
        let boundaries = Boundaries::current(&prior_art).expect("valid boundaries");
        assert_eq!(boundaries.linux_io_composition_domains, 7);
        assert_eq!(boundaries.linux_io_composition_effects, 9);
        assert_eq!(boundaries.linux_io_composition_causal_nodes, 10);
        assert_eq!(boundaries.linux_io_composition_causal_edges, 9);
        assert_eq!(boundaries.linux_io_composition_credit_classes, 8);
        assert_eq!(boundaries.linux_io_composition_credit_units, 9);
        assert!(!boundaries.retained_workload_identity_preserved);
        assert!(!boundaries.retained_effects_in_composition_cohort);
        assert!(!boundaries.registry_multi_domain_binding);
        assert_eq!(boundaries.stage5b_relation, "component_consistency");
        assert!(!boundaries.stage5b_same_boot);
        assert!(!boundaries.identity_preserving_stage5b_composition);
        assert!(!boundaries.real_dma_primary);
        assert!(boundaries.same_boot_runtime_fs_identity_observed);
        assert_eq!(boundaries.same_boot_runtime_fs_effects, 6);
        assert_eq!(boundaries.same_boot_runtime_fs_registry_domains, 3);
        assert!(boundaries.same_boot_runtime_fs_real_dma_observed);
        assert!(boundaries.same_boot_runtime_fs_precommit_revoke_wins_observed);
        assert!(!boundaries.same_boot_runtime_fs_all_fault_paths_observed);
        assert!(!boundaries.same_boot_runtime_fs_irq_observed);
        assert_eq!(boundaries.same_boot_runtime_fs_smp_vcpus, 1);
        assert!(boundaries.same_boot_runtime_fs_real_user_service_crash_observed);
        assert_eq!(boundaries.stage7b_concurrency_races_checked, 14);
        assert_eq!(boundaries.stage7b_fault_cells_checked, 20);
        assert_eq!(boundaries.stage7b_scale_points_checked, 14);
        assert_eq!(boundaries.stage7b_performance_cases_observed, 29);
        assert_eq!(boundaries.stage7b_performance_claim, "Observed");
        assert_eq!(boundaries.stage7b_prior_art_rows_checked, 16);
        assert_eq!(boundaries.stage7b_prior_art_full_text, 15);
        assert_eq!(boundaries.stage7b_prior_art_metadata_only, 1);
        assert_eq!(boundaries.stage7b_contribution_verdict, "narrow");
        assert!(!boundaries.novelty_established);
        assert!(!boundaries.first_established);
        assert!(!boundaries.proved_established);
        assert!(!boundaries.smp_checked);
        assert!(!boundaries.hardware_cycles_observed);
        assert!(!boundaries.lock_freedom_established);
        assert!(!boundaries.durable_external_effects_covered);
        assert!(!boundaries.linux_breadth_established);
        assert!(!boundaries.full_production_adapter_equivalence_established);

        let json = serde_json::to_value(boundaries).expect("serialize manifest boundaries");
        assert_eq!(json["linux_io_composition_causal_nodes"], 10);
        assert_eq!(json["linux_io_composition_causal_edges"], 9);
        assert_eq!(json["linux_io_composition_credit_classes"], 8);
        assert_eq!(json["linux_io_composition_credit_units"], 9);
        assert_eq!(json["real_dma_primary"], false);
        assert_eq!(json["same_boot_runtime_fs_identity_observed"], true);
        assert_eq!(json["same_boot_runtime_fs_effects"], 6);
        assert_eq!(json["same_boot_runtime_fs_registry_domains"], 3);
        assert_eq!(json["same_boot_runtime_fs_real_dma_observed"], true);
        assert_eq!(
            json["same_boot_runtime_fs_precommit_revoke_wins_observed"],
            true
        );
        assert_eq!(json["same_boot_runtime_fs_all_fault_paths_observed"], false);
        assert_eq!(json["same_boot_runtime_fs_irq_observed"], false);
        assert_eq!(json["same_boot_runtime_fs_smp_vcpus"], 1);
        assert_eq!(
            json["same_boot_runtime_fs_real_user_service_crash_observed"],
            true
        );
        assert_eq!(json["stage7b_contribution_verdict"], "narrow");
        assert_eq!(json["stage7b_performance_claim"], "Observed");
    }

    #[test]
    fn stale_and_markerless_artifacts_are_rejected() {
        let root = fixture();
        let sentinel = root.join("sentinel");
        let artifact = root.join("artifact.log");
        fs::write(&artifact, "PASS\n").expect("write artifact");
        thread::sleep(Duration::from_millis(5));
        fs::write(&sentinel, "start\n").expect("write sentinel");
        let started = fs::metadata(&sentinel)
            .expect("sentinel metadata")
            .modified()
            .expect("sentinel timestamp");
        assert!(validate_artifact(&root, "artifact.log", Some("PASS"), started).is_err());

        thread::sleep(Duration::from_millis(5));
        fs::write(&artifact, "WRONG\n").expect("rewrite artifact");
        assert!(validate_artifact(&root, "artifact.log", Some("PASS"), started).is_err());

        thread::sleep(Duration::from_millis(5));
        fs::write(&artifact, "PASS\n").expect("rewrite artifact with marker");
        let checked = validate_artifact(&root, "artifact.log", Some("PASS"), started)
            .expect("fresh marked artifact");
        assert_eq!(checked.bytes, 5);
        assert_eq!(checked.sha256.len(), 64);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn model_spec_artifacts_require_exact_verifier_version_lines() {
        let root = fixture();
        let started = SystemTime::now();
        thread::sleep(Duration::from_millis(5));

        let tlc = root.join("Cser-tlc.log");
        fs::write(
            &tlc,
            "TLC2 Version substitute\nModel checking completed. No error has been found.\n",
        )
        .expect("write TLC log");
        let error = validate_artifact(
            &root,
            "Cser-tlc.log",
            Some("Model checking completed. No error has been found."),
            started,
        )
        .expect_err("wrong TLC build must be rejected")
        .to_string();
        assert!(error.contains("pinned TLC version line"));
        fs::write(
            &tlc,
            format!(
                "{TLA_TOOLCHAIN_VERSION_LINE}\nModel checking completed. No error has been found.\n"
            ),
        )
        .expect("write exact TLC log");
        validate_artifact(
            &root,
            "Cser-tlc.log",
            Some("Model checking completed. No error has been found."),
            started,
        )
        .expect("exact TLC build line");

        let pluscal = root.join("Cser-pluscal.log");
        fs::write(
            &pluscal,
            "pcal.trans Version substitute\nTranslation completed.\n",
        )
        .expect("write PlusCal log");
        let error = validate_artifact(
            &root,
            "Cser-pluscal.log",
            Some("Translation completed."),
            started,
        )
        .expect_err("wrong PlusCal build must be rejected")
        .to_string();
        assert!(error.contains("pinned PlusCal version line"));
        fs::write(
            &pluscal,
            format!("{PLUSCAL_VERSION_LINE}\nTranslation completed.\n"),
        )
        .expect("write exact PlusCal log");
        validate_artifact(
            &root,
            "Cser-pluscal.log",
            Some("Translation completed."),
            started,
        )
        .expect("exact PlusCal build line");
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn source_fingerprint_binds_paths_contents_and_modes() {
        let root = fixture();
        let first = root.join("first");
        let second = root.join("second");
        fs::write(&first, "alpha").expect("write first source");
        fs::write(&second, "beta").expect("write second source");
        let paths = vec![PathBuf::from("first"), PathBuf::from("second")];
        let baseline = fingerprint_paths(&root, &paths).expect("baseline fingerprint");

        fs::write(&second, "gamma").expect("change source contents");
        assert_ne!(
            fingerprint_paths(&root, &paths).expect("content fingerprint"),
            baseline
        );
        fs::write(&second, "beta").expect("restore source contents");
        let mut permissions = fs::metadata(&first).expect("first metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&first, permissions).expect("change source mode");
        assert_ne!(
            fingerprint_paths(&root, &paths).expect("mode fingerprint"),
            baseline
        );
        assert_ne!(
            fingerprint_paths(&root, &paths[..1]).expect("path-set fingerprint"),
            baseline
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn start_record_strictly_binds_source_environment_and_nonce() {
        let source = SourceSnapshot {
            revision: String::from("revision"),
            source_sha256: "a".repeat(64),
            worktree_dirty: true,
        };
        let environment = VerificationEnvironment {
            invocation: String::from("./x verify"),
            nexus_rebuild: Some(String::from("1")),
        };
        let record = start_record(&source, &environment);
        validate_start_record(&record, &source, Some(&environment)).expect("matching start record");
        validate_completion_token_value(&record, &"f".repeat(64))
            .expect("matching orchestration token");
        assert!(validate_completion_token_value(&record, &"e".repeat(64)).is_err());
        assert!(validate_completion_token_value(&record, "short").is_err());
        validate_start_record(&record, &source, None)
            .expect("the bound start record is structurally valid without an environment check");

        let mut changed_source = source.clone();
        changed_source.source_sha256 = "b".repeat(64);
        assert!(validate_start_record(&record, &changed_source, Some(&environment)).is_err());

        let changed_environment = VerificationEnvironment {
            invocation: String::from("private manifest invocation"),
            nexus_rebuild: Some(String::from("1")),
        };
        assert!(validate_start_record(&record, &source, Some(&changed_environment)).is_err());

        let changed_rebuild = VerificationEnvironment {
            invocation: String::from("./x verify"),
            nexus_rebuild: None,
        };
        assert!(validate_start_record(&record, &source, Some(&changed_rebuild)).is_err());

        let mut corrupted = record.clone();
        corrupted.nonce = "0".repeat(64);
        assert!(validate_start_record(&corrupted, &source, Some(&environment)).is_err());

        let mut corrupted = record;
        corrupted.orchestration_token_sha256 = "0".repeat(64);
        assert!(validate_start_record(&corrupted, &source, Some(&environment)).is_err());
    }

    #[test]
    fn gate_receipts_bind_the_start_stage_chain_and_exact_artifacts() {
        let source = SourceSnapshot {
            revision: String::from("revision"),
            source_sha256: "a".repeat(64),
            worktree_dirty: true,
        };
        let environment = VerificationEnvironment {
            invocation: String::from("./x verify"),
            nexus_rebuild: Some(String::from("1")),
        };
        let start = start_record(&source, &environment);
        let artifacts = vec![Artifact {
            path: String::from("target/verification/Cser-tlc.log"),
            bytes: 17,
            sha256: "b".repeat(64),
        }];
        let model = gate_receipt(
            MODEL_SPEC_SCHEMA,
            &start,
            ["reference-model", "formal-specifications"],
            None,
            artifacts.clone(),
        )
        .expect("model/spec receipt");
        validate_gate_receipt(
            &model,
            MODEL_SPEC_SCHEMA,
            &start,
            &["reference-model", "formal-specifications"],
            None,
            &artifacts,
        )
        .expect("valid model/spec receipt");

        let model_sha256 = sha256(&serde_json::to_vec(&model).expect("serialize model receipt"));
        let complete = gate_receipt(
            COMPLETE_SCHEMA,
            &start,
            COMPLETE_STAGES,
            Some(model_sha256.clone()),
            artifacts.clone(),
        )
        .expect("completion receipt");
        validate_gate_receipt(
            &complete,
            COMPLETE_SCHEMA,
            &start,
            &COMPLETE_STAGES,
            Some(&model_sha256),
            &artifacts,
        )
        .expect("valid completion receipt");

        let mut changed_artifacts = artifacts.clone();
        changed_artifacts[0].sha256 = "c".repeat(64);
        assert!(
            validate_gate_receipt(
                &complete,
                COMPLETE_SCHEMA,
                &start,
                &COMPLETE_STAGES,
                Some(&model_sha256),
                &changed_artifacts,
            )
            .is_err()
        );

        let wrong_prerequisite = "d".repeat(64);
        assert!(
            validate_gate_receipt(
                &complete,
                COMPLETE_SCHEMA,
                &start,
                &COMPLETE_STAGES,
                Some(&wrong_prerequisite),
                &artifacts,
            )
            .is_err()
        );

        let mut extra_artifact = complete.clone();
        extra_artifact.artifacts.push(artifacts[0].clone());
        assert!(
            validate_gate_receipt(
                &extra_artifact,
                COMPLETE_SCHEMA,
                &start,
                &COMPLETE_STAGES,
                Some(&model_sha256),
                &artifacts,
            )
            .is_err()
        );

        let mut invalid_time = complete.clone();
        invalid_time.completed_unix_nanos = start.started_unix_nanos - 1;
        assert!(
            validate_gate_receipt(
                &invalid_time,
                COMPLETE_SCHEMA,
                &start,
                &COMPLETE_STAGES,
                Some(&model_sha256),
                &artifacts,
            )
            .is_err()
        );

        let mut wrong_nonce = complete;
        wrong_nonce.run_nonce = "e".repeat(64);
        assert!(
            validate_gate_receipt(
                &wrong_nonce,
                COMPLETE_SCHEMA,
                &start,
                &COMPLETE_STAGES,
                Some(&model_sha256),
                &artifacts,
            )
            .is_err()
        );
    }

    #[test]
    fn begin_cleanup_removes_every_expected_artifact_and_propagates_real_errors() {
        let root = fixture();
        let specs = ["Cser", "CompositionCser"];
        write_required_evidence(&root, &specs);
        let unrelated = root.join("target/verification/unrelated.log");
        fs::write(&unrelated, "keep\n").expect("write unrelated evidence");

        clear_expected_evidence(&root, &specs).expect("clear expected evidence");
        for relative in [
            String::from(SENTINEL),
            String::from(FORMAL_VERIFIER_RECEIPT),
            String::from(MODEL_SPEC_RECEIPT),
            String::from(COMPLETION_RECEIPT),
            String::from(OUTPUT),
        ]
        .into_iter()
        .chain(required_artifacts(&specs).into_iter().map(|(path, _)| path))
        {
            assert!(!root.join(relative).exists());
        }
        assert!(unrelated.is_file());
        clear_expected_evidence(&root, &specs).expect("not-found cleanup is idempotent");

        fs::create_dir_all(root.join(OUTPUT)).expect("create non-file manifest path");
        let error = clear_expected_evidence(&root, &specs)
            .expect_err("a non-NotFound cleanup error must propagate");
        assert!(
            error
                .to_string()
                .contains("remove stale verification evidence")
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn manifest_rejects_fresh_artifacts_without_gate_completion_receipts() {
        let root = fixture();
        let git = |args: &[&str]| {
            let status = Command::new("git")
                .current_dir(&root)
                .args(args)
                .status()
                .expect("run fixture git");
            assert!(status.success(), "fixture git command failed: {args:?}");
        };
        git(&["init", "-q"]);
        fs::write(
            root.join(".gitignore"),
            "target/\nkernel/nexus-ostd/artifacts/\nexperiments/ostd-virtio-cser-spike/artifacts/\n",
        )
        .expect("write ignore file");
        fs::write(root.join("tracked"), "tracked\n").expect("write tracked source");
        copy_toolchain_fixture(&root);
        git(&["add", "."]);
        git(&[
            "-c",
            "user.name=Nexus Test",
            "-c",
            "user.email=nexus@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ]);

        let source = source_snapshot(&root).expect("fixture source snapshot");
        let environment = optional_verification_environment()
            .expect("read verification environment")
            .unwrap_or_else(|| VerificationEnvironment {
                invocation: String::from("./x verify"),
                nexus_rebuild: None,
            });
        let start = start_record(&source, &environment);
        let sentinel = root.join(SENTINEL);
        fs::create_dir_all(sentinel.parent().expect("sentinel parent"))
            .expect("create sentinel parent");
        fs::write(
            &sentinel,
            serde_json::to_vec_pretty(&start).expect("serialize start record"),
        )
        .expect("write start record");

        thread::sleep(Duration::from_millis(5));
        let specs = ["Cser", "CompositionCser"];
        for (relative, marker) in required_artifacts(&specs) {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().expect("artifact parent"))
                .expect("create artifact parent");
            let mut contents = format!("{}\n", marker.unwrap_or("fixture raw artifact"));
            if path.to_string_lossy().ends_with("-tlc.log") {
                contents.push_str(TLA_TOOLCHAIN_VERSION_LINE);
                contents.push('\n');
            }
            if path.to_string_lossy().ends_with("-pluscal.log") {
                contents.push_str(PLUSCAL_VERSION_LINE);
                contents.push('\n');
            }
            fs::write(path, contents).expect("write fresh marked artifact");
        }
        fs::write(
            root.join("target/verification/stage7b/prior-art.json"),
            crate::stage7b_prior_art::accepted_receipt_json()
                .expect("serialize accepted prior-art receipt"),
        )
        .expect("write structured prior-art fixture");

        let token = "f".repeat(64);
        let error = write_authorized(&root, &specs, &token, &environment)
            .expect_err("artifacts assembled by focused commands must not publish a manifest");
        assert!(
            error
                .to_string()
                .contains("required formal verifier receipt")
        );
        assert!(!root.join(OUTPUT).exists());

        let start_bytes = fs::read(&sentinel).expect("read start record");
        let verifier = formal_verifier_receipt(&start, sha256(&start_bytes));
        let verifier_bytes =
            serde_json::to_vec_pretty(&verifier).expect("serialize formal verifier receipt");
        fs::write(root.join(FORMAL_VERIFIER_RECEIPT), &verifier_bytes)
            .expect("write formal verifier receipt");
        let error = write_authorized(&root, &specs, &token, &environment)
            .expect_err("formal receipt without model/spec receipt must not publish a manifest");
        assert!(
            error
                .to_string()
                .contains("required model/spec completion receipt")
        );

        let sentinel_time = fs::metadata(&sentinel)
            .expect("sentinel metadata")
            .modified()
            .expect("sentinel timestamp");
        let model_artifacts =
            validate_artifacts(&root, &model_spec_artifacts(&specs), sentinel_time)
                .expect("model/spec artifacts");
        let model_receipt = gate_receipt(
            MODEL_SPEC_SCHEMA,
            &start,
            ["reference-model", "formal-specifications"],
            Some(sha256(&verifier_bytes)),
            model_artifacts,
        )
        .expect("model/spec receipt");
        let model_bytes =
            serde_json::to_vec_pretty(&model_receipt).expect("serialize model/spec receipt");
        fs::write(root.join(MODEL_SPEC_RECEIPT), &model_bytes).expect("write model/spec receipt");
        let error = write_authorized(&root, &specs, &token, &environment)
            .expect_err("a partial run without final completion must not publish a manifest");
        assert!(
            error
                .to_string()
                .contains("required verification completion receipt")
        );

        let artifacts = validate_artifacts(&root, &required_artifacts(&specs), sentinel_time)
            .expect("full artifact inventory");
        let completion = gate_receipt(
            COMPLETE_SCHEMA,
            &start,
            COMPLETE_STAGES,
            Some(sha256(&model_bytes)),
            artifacts,
        )
        .expect("completion receipt");
        fs::write(
            root.join(COMPLETION_RECEIPT),
            serde_json::to_vec_pretty(&completion).expect("serialize completion receipt"),
        )
        .expect("write completion receipt");
        let wrong_token = "e".repeat(64);
        let error = write_authorized(&root, &specs, &wrong_token, &environment)
            .expect_err("a later process without the run token must not publish a manifest");
        assert!(error.to_string().contains("does not authorize"));
        assert!(!root.join(OUTPUT).exists());
        write_authorized(&root, &specs, &token, &environment)
            .expect("authorized manifest after a fully sealed run");
        write_authorized(&root, &specs, &token, &environment)
            .expect("authorized manifest recheck is repeatable inside the run");

        fs::write(
            root.join("kernel/nexus-ostd/artifacts/serial.log"),
            "COMPOSITION_SLICE PASS\nmarker-preserving replacement\n",
        )
        .expect("replace a sealed artifact");
        let error = write_authorized(&root, &specs, &token, &environment)
            .expect_err("a marker-preserving artifact replacement must break the receipt");
        assert!(error.to_string().contains("artifacts changed"));
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn stable_read_rejects_content_metadata_and_path_changes() {
        let root = fixture();
        let artifact = root.join("artifact.log");
        fs::write(&artifact, "PASS\n").expect("write artifact");
        let error = read_regular_file_stable_with(&artifact, "artifact", |path| {
            fs::write(path, "FAIL and grow\n")?;
            Ok(())
        })
        .expect_err("length-changing rewrite must be rejected");
        assert!(error.to_string().contains("changed while it was read"));

        fs::write(&artifact, "PASS\n").expect("restore artifact");
        let replacement = root.join("replacement.log");
        let error = read_regular_file_stable_with(&artifact, "artifact", |path| {
            fs::rename(path, &replacement)?;
            fs::write(path, "PASS\n")?;
            Ok(())
        })
        .expect_err("path replacement must be rejected");
        assert!(error.to_string().contains("changed while it was read"));
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn source_snapshot_includes_untracked_nonignored_files_but_not_ignored_outputs() {
        let root = fixture();
        let git = |args: &[&str]| {
            let status = Command::new("git")
                .current_dir(&root)
                .args(args)
                .status()
                .expect("run fixture git");
            assert!(status.success(), "fixture git command failed: {args:?}");
        };
        git(&["init", "-q"]);
        fs::write(root.join(".gitignore"), "ignored.log\n").expect("write ignore file");
        fs::write(root.join("tracked"), "tracked\n").expect("write tracked source");
        git(&["add", ".gitignore", "tracked"]);
        git(&[
            "-c",
            "user.name=Nexus Test",
            "-c",
            "user.email=nexus@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ]);

        let clean = source_snapshot(&root).expect("clean snapshot");
        assert!(!clean.worktree_dirty);
        fs::write(root.join("ignored.log"), "ignored output\n").expect("write ignored output");
        assert_eq!(source_snapshot(&root).expect("ignored snapshot"), clean);

        fs::write(root.join("untracked"), "new source\n").expect("write untracked source");
        let with_untracked = source_snapshot(&root).expect("untracked snapshot");
        assert!(with_untracked.worktree_dirty);
        assert_ne!(with_untracked.source_sha256, clean.source_sha256);
        fs::remove_dir_all(root).expect("remove fixture");
    }
}
