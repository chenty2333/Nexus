//! The deliberately small, direct production-system runner.
//!
//! This module is the only host-side owner of the OSTD production sequence;
//! all OSDK, QEMU, and TPM steps below are explicit.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

pub(crate) type Result<T> = std::result::Result<T, Box<dyn Error>>;

const KERNEL: &str = "kernel/nexus-ostd";
const SYSTEM_OUTPUT: &str = "kernel/nexus-ostd/target/nexus/system";
const FIXTURE_REVISION: &str = "041113950b5e45e63099a164c7d1915ccb8a1018";
const FIXTURE_ARCHIVE_SHA256: &str =
    "6f35a75b26851aac209b102585f80bf18c2629aec3f91e42d2ddee030b1a2a75";
const FIXTURE_CATALOG: &str = "c510695985b0de4592242dcfca36fb52eafc0e0c53fbd214e9dd46799464424b";
const FIXTURE_HEAD: &str = "21442cc39e8704bf2fdfa860053cb40aab3c88779d8efd1ea7a39bcfd3fd7bd7";
const FIXTURE_JOURNAL_SHA256: &str =
    "b3156d2dcbb622c6a12a8e155fc398357bbf1151b01834e1c7549fffc53bc898";
const RUNTIME_FS_SHA256: &str = "9357413ed9a96a23af1750cc304265dd7dd1835eb58eb1fb50119cd80d0bc8ca";

pub(crate) fn check(root: &Path) -> Result<()> {
    let _lock = SystemLock::acquire(root)?;
    let image = image(root)?;
    ensure_image(root, &image)?;
    kernel_checks(root, &image)
}

pub(crate) fn build(root: &Path) -> Result<()> {
    let _lock = SystemLock::acquire(root)?;
    let image = image(root)?;
    ensure_image(root, &image)?;
    kernel_checks(root, &image)?;
    build_scheme(root, &image, "cser-production")
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let _lock = SystemLock::acquire(root)?;
    let image = image(root)?;
    ensure_image(root, &image)?;
    kernel_checks(root, &image)?;
    run_pio_ktest(root, &image)?;
    let run_dir = system_output(root);
    prepare_system_output(&run_dir)?;
    run_focused_reply(root, &image, &run_dir)?;
    run_focused_dma(root, &image, &run_dir)?;
    let catalog = catalog_digest(root, &image)?;
    schema8_negative_boot(root, &image, &run_dir, &catalog)?;
    run_four_boots(root, &image, &run_dir, &catalog)?;
    Ok(())
}

pub(crate) fn clean(root: &Path) -> Result<()> {
    let kernel_target = root.join(KERNEL).join("target");
    if kernel_target.exists() {
        fs::remove_dir_all(&kernel_target)?;
    }
    Ok(())
}

pub(crate) fn lock(root: &Path) -> Result<SystemLock> {
    SystemLock::acquire(root)
}

/// One OSDK/QEMU run owns mutable kernel targets, media, and the host TPM
/// socket. The lock lives in Git metadata so cleanup cannot unlink the held
/// inode; Cargo's own locks continue to govern ordinary host-only work.
pub(crate) struct SystemLock {
    _file: File,
}

impl SystemLock {
    fn acquire(root: &Path) -> Result<Self> {
        let git_path = output(
            root,
            "git",
            &["rev-parse", "--git-path", "nexus-system.lock"],
        )?;
        let git_path = PathBuf::from(git_path.trim());
        let path = if git_path.is_absolute() {
            git_path
        } else {
            root.join(git_path)
        };
        let directory = path.parent().ok_or("Git lock path has no parent")?;
        fs::create_dir_all(directory)?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        file.try_lock()
            .map_err(|_| "another cargo nexus kernel/system operation is running")?;
        Ok(Self { _file: file })
    }
}

#[derive(Debug, Clone)]
struct Image {
    reference: String,
    rustc_commit: String,
    rustc_dist_date: String,
}

fn image(root: &Path) -> Result<Image> {
    let vv = output(root, "rustc", &["-Vv"])?;
    let values = vv
        .lines()
        .filter_map(|line| line.split_once(": "))
        .collect::<BTreeMap<_, _>>();
    let commit = values
        .get("commit-hash")
        .ok_or("rustc -Vv omitted commit-hash")?
        .to_string();
    if !valid_hex(&commit, 40) {
        return Err("rustc -Vv returned malformed commit hash".into());
    }
    let sysroot = output(root, "rustc", &["--print", "sysroot"])?;
    let manifest =
        PathBuf::from(sysroot.trim()).join("lib/rustlib/multirust-channel-manifest.toml");
    let dist_date = fs::read_to_string(&manifest)?
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("date = \"")
                .and_then(|value| value.strip_suffix('\"'))
        })
        .ok_or("rustup manifest omitted dist date")?
        .to_string();
    if !valid_date(&dist_date) {
        return Err("rustup manifest has malformed dist date".into());
    }
    let build_inputs = docker_build_inputs_hash(root)?;
    Ok(Image {
        reference: format!("nexus/nexus-ostd:{dist_date}-{}", &build_inputs[..16]),
        rustc_commit: commit,
        rustc_dist_date: dist_date,
    })
}

/// This is the complete set copied into the only Docker build, plus the
/// patch configuration it consumes.  Tagging it makes a local retag unable
/// to satisfy a changed build input.
fn docker_build_inputs_hash(root: &Path) -> Result<String> {
    let mut files = Vec::new();
    for relative in [
        ".dockerignore",
        "Dockerfile",
        "Cargo.toml",
        "Cargo.lock",
        "patches",
        "crates/cser-core",
        "crates/cser-model",
        "crates/nexus-ostd-virtio",
        "tools/xtask",
        "kernel/nexus-ostd",
    ] {
        let path = root.join(relative);
        if path.is_file() {
            files.push(path);
        } else if path.is_dir() {
            collect_docker_inputs(&path, &mut files)?;
        } else {
            return Err(format!("Docker build input is missing: {}", path.display()).into());
        }
    }
    files.sort();
    let mut material = Vec::new();
    for file in files {
        let relative = file.strip_prefix(root)?;
        material.extend_from_slice(relative.as_os_str().as_encoded_bytes());
        material.push(0);
        material.extend_from_slice(sha256(root, &file)?.as_bytes());
        material.push(0);
    }
    sha256_bytes(root, &material)
}

fn collect_docker_inputs(current: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        let name = entry.file_name();
        if kind.is_symlink() {
            return Err(
                format!("Docker build input contains a symlink: {}", path.display()).into(),
            );
        }
        if kind.is_dir() {
            if name == "target" || name == "__pycache__" {
                continue;
            }
            collect_docker_inputs(&path, out)?;
        } else if kind.is_file() {
            if path.extension().and_then(|extension| extension.to_str()) == Some("pyc")
                || path
                    .parent()
                    .is_some_and(|parent| parent.ends_with("guest"))
                    && matches!(
                        path.extension().and_then(|ext| ext.to_str()),
                        Some("bin" | "elf")
                    )
            {
                continue;
            }
            out.push(path);
        } else {
            return Err("Docker build input has an unsupported entry".into());
        }
    }
    Ok(())
}

fn ensure_image(root: &Path, image: &Image) -> Result<()> {
    let inspected = Command::new("docker")
        .current_dir(root)
        .args(["image", "inspect", &image.reference])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !inspected.success() || std::env::var("NEXUS_REBUILD").as_deref() == Ok("1") {
        status(
            root,
            "docker",
            &[
                "build",
                "--platform",
                "linux/amd64",
                "--build-arg",
                &format!("RUST_NIGHTLY_DATE={}", image.rustc_dist_date),
                "--tag",
                &image.reference,
                ".",
            ],
        )?;
    }
    let image_vv = command_output(
        root,
        "docker",
        &[
            "run".into(),
            "--rm".into(),
            "--network".into(),
            "none".into(),
            image.reference.clone(),
            "rustc".into(),
            "-Vv".into(),
        ],
    )?;
    let image_commit = image_vv
        .lines()
        .find_map(|line| line.strip_prefix("commit-hash: "))
        .ok_or("image rustc -Vv omitted commit hash")?;
    if image_commit != image.rustc_commit {
        return Err("Docker nightly commit does not match host rustc".into());
    }
    Ok(())
}

fn kernel_checks(root: &Path, image: &Image) -> Result<()> {
    for feature in [
        "cser-production",
        "cser-core-reply-recovery",
        "cser-core-dma-recovery",
        "cser-pio-journal-ktest",
    ] {
        container(
            root,
            image,
            &format!(
                "cd /work && cargo check --locked --offline --target x86_64-unknown-none --no-default-features --features {feature}"
            ),
            false,
        )?;
    }
    container(root, image, "cd /work && cargo osdk check --locked", false)
}

fn prepare_runner(root: &Path) -> Result<String> {
    let source = root.join(KERNEL).join("osdk-runner-base");
    let destination = root.join(KERNEL).join("target/osdk/nexus-kernel-run-base");
    if destination.exists() {
        fs::remove_dir_all(&destination)?;
    }
    copy_tree(&source, &destination)?;
    let before = runner_controls(root, &destination)?;
    let lock_path = destination.join("Cargo.lock");
    let mut permissions = fs::metadata(&lock_path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&lock_path, permissions)?;
    Ok(before)
}

fn build_scheme(root: &Path, image: &Image, scheme: &str) -> Result<()> {
    let runner_before = prepare_runner(root)?;
    let result = container(
        root,
        image,
        &format!("cd /work && cargo osdk build --scheme {scheme}"),
        false,
    );
    let runner = root.join(KERNEL).join("target/osdk/nexus-kernel-run-base");
    let runner_result = assert_runner_unchanged(root, &runner, &runner_before);
    result?;
    runner_result
}

fn assert_runner_unchanged(root: &Path, runner: &Path, before: &str) -> Result<()> {
    if runner_controls(root, runner)? != before {
        return Err("OSDK rewrote a controlled runner input".into());
    }
    Ok(())
}

fn run_pio_ktest(root: &Path, image: &Image) -> Result<()> {
    let runner_before = prepare_runner(root)?;
    let runner = root.join(KERNEL).join("target/osdk/nexus-kernel-run-base");
    let result = container_output(
        root,
        image,
        "cd /work; cp /root/ovmf/release/OVMF_VARS.fd \"$HOME/OVMF_VARS.fd\"; timeout --signal=TERM --kill-after=2s 300s cargo osdk test --scheme cser-pio-journal-ktest cser_pio_journal_gate",
        false,
    );
    let runner_result = assert_runner_unchanged(root, &runner, &runner_before);
    let out = result?;
    runner_result?;
    let clean = out.replace('\r', "");
    let test_passes = clean
        .lines()
        .filter(|line| {
            line.contains("test nexus_kernel::core_pio_journal::tests::cser_pio_journal_gate")
                && !line.contains("FAILED")
        })
        .count();
    let summaries = clean
        .lines()
        .filter(|line| line.contains("test result: ok. 1 passed; 0 failed"))
        .count();
    if test_passes != 1
        || summaries != 1
        || clean.contains("cser_pio_journal_gate ... FAILED")
        || clean.contains("test result: FAILED")
    {
        return Err("PIO journal ktest did not report its single passing gate".into());
    }
    Ok(())
}

fn prepare_system_output(run_dir: &Path) -> Result<()> {
    if run_dir.exists() {
        fs::remove_dir_all(run_dir)?;
    }
    fs::create_dir_all(run_dir)?;
    write_len(&run_dir.join("journal.raw"), 4 * 1024 * 1024)?;
    write_len(&run_dir.join("outbox.raw"), 4 * 1024 * 1024)?;
    write_len(&run_dir.join("ram.raw"), 1024 * 1024 * 1024)?;
    Ok(())
}

fn run_focused_reply(root: &Path, image: &Image, run_dir: &Path) -> Result<()> {
    build_scheme(root, image, "cser-core-reply-recovery")?;
    capture(
        root,
        image,
        run_dir,
        "reply-evidence",
        "cser-core-reply-recovery",
        60,
        false,
    )?;
    let marker = exact_marker(
        &run_dir.join("reply-evidence-serial.log"),
        "CSER_CORE_OSTD_TASK_RECOVERY PASS",
        &[
            "death=task-return",
            "exact_reap=true",
            "settlement_claim=true",
            "second_crash=true",
            "reconcile_without_second_intent=true",
            "physical_reply=true",
            "real_waiter_wake=true",
            "production_profile=false",
            "legacy_runtime=false",
            "live_dual_write=false",
            "api_profile=6",
            "scoped_providers=true",
            "exact_verifier_binding=true",
            "reboot_persistence=false",
        ],
    )?;
    if marker.is_empty() {
        return Err("empty reply marker".into());
    }
    Ok(())
}

fn run_focused_dma(root: &Path, image: &Image, run_dir: &Path) -> Result<()> {
    build_scheme(root, image, "cser-core-dma-recovery")?;
    capture(
        root,
        image,
        run_dir,
        "dma-evidence",
        "cser-core-dma-recovery",
        90,
        false,
    )?;
    let serial = fs::read_to_string(run_dir.join("dma-evidence-serial.log"))?;
    let trace = fs::read_to_string(run_dir.join("dma-evidence-qemu-debug.log"))?;
    assert_dma_irq_unsupported(&serial, &trace)
}

fn assert_dma_irq_unsupported(serial: &str, trace: &str) -> Result<()> {
    const PREFIX: &str = "CSER_CORE_DMA_IRQ UNSUPPORTED";
    const REQUIRED: &[&str] = &[
        "outcome=FAIL_CLOSED",
        "reason=controller_pending_synchronization_unsupported",
        "pci_intx_masked=true",
        "queue_published=false",
        "request_owner_created=false",
        "irq_mapping_retained=true",
        "qemu_evidence=false",
        "physical_hardware_evidence=false",
    ];
    let records = serial
        .lines()
        .filter(|line| tokens_match(line, PREFIX))
        .collect::<Vec<_>>();
    if records.len() != 1 {
        return Err("focused DMA did not report exactly one UNSUPPORTED record".into());
    }
    for required in REQUIRED {
        if !has_unique_token(records[0], required) {
            return Err(format!("unsupported DMA record lacks unique token {required}").into());
        }
    }
    for forbidden in [
        "CSER_CORE_DMA HardwareClosure PASS",
        "CSER_CORE_DMA_OSTD_QEMU PASS",
        "CSER_CORE_DMA_IRQ SUPPORTED_CLOSURE",
        "CSER_CORE_DMA_IRQ SUPPORTED_QEMU_COMPLETION",
    ] {
        if serial.contains(forbidden) {
            return Err(
                format!("unsupported DMA lane emitted forbidden marker {forbidden}").into(),
            );
        }
    }
    for forbidden in ["virtio_pci_notify_write", "virtio_blk_handle_read"] {
        if trace.contains(forbidden) {
            return Err(format!("unsupported DMA lane escaped through {forbidden}").into());
        }
    }
    if trace.contains("vtd_dmar_fault") {
        return Err("focused DMA emitted a VT-d fault".into());
    }
    Ok(())
}

fn catalog_digest(root: &Path, image: &Image) -> Result<String> {
    let digest = container_output(
        root,
        image,
        "cd /repo && CARGO_TARGET_DIR=/tmp/nexus-catalog-target cargo run --offline -q --locked --manifest-path Cargo.toml -p cser-core --features std --bin cser-catalog-digest",
        false,
    )?;
    let digest = digest.trim().to_string();
    if !valid_hex(&digest, 64) {
        return Err("cser-catalog-digest returned malformed output".into());
    }
    Ok(digest)
}

fn schema8_negative_boot(root: &Path, image: &Image, run_dir: &Path, catalog: &str) -> Result<()> {
    let original = build_schema8_fixture(root, image, run_dir)?;
    let state = run_dir.join("tpmstate");
    status(
        root,
        "bash",
        &[
            script(root, "provision-cser-tpm-nv.sh")?
                .to_str()
                .ok_or("non-utf8 script")?,
            state.to_str().ok_or("non-utf8 state")?,
            FIXTURE_CATALOG,
            "5",
            FIXTURE_HEAD,
        ],
    )?;
    let before = snapshot_tpm(
        root,
        &state,
        &run_dir.join("schema8-negative-tpm-before.txt"),
    )?;
    capture(
        root,
        image,
        run_dir,
        "schema8-negative",
        "cser-production",
        90,
        true,
    )?;
    let after = snapshot_tpm(
        root,
        &state,
        &run_dir.join("schema8-negative-tpm-after.txt"),
    )?;
    if !tpm_snapshot_unchanged(&before, &after) {
        return Err("schema8 negative boot changed provisioned TPM NV state".into());
    }
    if fs::read(run_dir.join("journal.raw"))? != original {
        return Err("schema8 negative boot rewrote its journal".into());
    }
    let serial = run_dir.join("schema8-negative-serial.log");
    let migration = exact_marker(
        &serial,
        "CSER_CORE_SCHEMA8_MIGRATION_REQUIRED PASS",
        &[
            "trusted_tpm_candidate_selected=true",
            "current_binding_authorized=false",
            "selected_revision=5",
            &format!("selected_head={FIXTURE_HEAD}"),
            &format!("selected_catalog={FIXTURE_CATALOG}"),
            &format!("expected_catalog={catalog}"),
            "anchor_binding_match=false",
            "journal_schema=8",
            "typed_error=migration-required",
            "semantic_replay=false",
            "inferred_pairing=false",
            "pre_replay_quarantine=true",
            "bus_master_disabled=true",
            "intx_masked=true",
            "reset_status_zero=true",
            "iotlb_used_remapped_iova=true",
            "device_guard_retained=true",
            "production_registry=false",
            "device_activation=false",
            "arena_withheld=true",
            "queue_republish=false",
            "page_iova_reuse=false",
        ],
    )?;
    exact_marker(
        &serial,
        "CSER_CORE_PERSISTENT_FAIL_CLOSED",
        &[
            "reason=schema8-migration-required",
            "activation=blocked",
            "queue_republish=false",
            "page_iova_reuse=false",
        ],
    )?;
    let content = fs::read_to_string(&serial)?;
    if content.contains("CSER_CORE_PERSISTENT_BOOT")
        || content.contains("production_registry=single")
    {
        return Err("schema8 negative boot published production state".into());
    }
    assert_schema8_trace(
        &fs::read_to_string(run_dir.join("schema8-negative-qemu-debug.log"))?,
        &migration,
    )?;
    let negative_state = run_dir.join("schema8-negative-tpmstate");
    fs::rename(&state, negative_state)?;
    write_len(&run_dir.join("journal.raw"), 4 * 1024 * 1024)?;
    write_len(&run_dir.join("outbox.raw"), 4 * 1024 * 1024)?;
    Ok(())
}

fn build_schema8_fixture(root: &Path, image: &Image, run_dir: &Path) -> Result<Vec<u8>> {
    let source = run_dir.join("schema8-source");
    fs::create_dir_all(&source)?;
    let archive = source.join("source.tar");
    let archive_file = File::create(&archive)?;
    let archive_status = Command::new("git")
        .current_dir(root)
        .args(["archive", "--format=tar", FIXTURE_REVISION])
        .stdout(archive_file)
        .status()?;
    if !archive_status.success() || sha256(root, &archive)? != FIXTURE_ARCHIVE_SHA256 {
        return Err("archived predecessor source is not pinned".into());
    }
    status(
        root,
        "tar",
        &[
            "-xf",
            archive.to_str().ok_or("non-utf8 archive")?,
            "-C",
            source.to_str().ok_or("non-utf8 source")?,
        ],
    )?;
    fs::remove_file(&archive)?;
    let cargo_toml = source.join("Cargo.toml");
    let original = fs::read_to_string(&cargo_toml)?;
    let isolated = original
        .lines()
        .filter(|line| {
            !line.contains("cser-trace-conformance") && !line.contains("nexus-effect-peer-wire")
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&cargo_toml, isolated)?;
    let source_rel = source
        .strip_prefix(root.join(KERNEL))?
        .to_str()
        .ok_or("non-utf8 source")?;
    let logical_rel = format!("{source_rel}/profile4.journal");
    let origin = container_output(
        root,
        image,
        &format!(
            "cd /work/{source_rel}; CARGO_TARGET_DIR=/tmp/nexus-schema8-target cargo generate-lockfile --offline --manifest-path Cargo.toml; CARGO_TARGET_DIR=/tmp/nexus-schema8-target cargo run --offline -q --locked --manifest-path Cargo.toml -p cser-core --features std --bin cser-restart-fixture -- origin /work/{logical_rel}"
        ),
        false,
    )?;
    if origin.trim() != format!("5 {FIXTURE_HEAD}") {
        return Err("pinned predecessor encoder returned wrong coordinates".into());
    }
    let catalog = container_output(
        root,
        image,
        &format!(
            "cd /work/{source_rel}; cargo run --offline -q --locked --manifest-path Cargo.toml -p cser-core --features std --bin cser-catalog-digest"
        ),
        false,
    )?;
    if catalog.trim() != FIXTURE_CATALOG {
        return Err("pinned predecessor catalog differs".into());
    }
    let logical = fs::read(source.join("profile4.journal"))?;
    if logical.len() != 1289
        || sha256(root, &source.join("profile4.journal"))? != FIXTURE_JOURNAL_SHA256
        || !logical.starts_with(b"CSERJR8\0")
        || hex(&logical[logical.len() - 32..]) != FIXTURE_HEAD
    {
        return Err("pinned predecessor journal differs".into());
    }
    let payload = sha256(root, &source.join("profile4.journal"))?;
    let mut header = hex_bytes(&format!(
        "4353455250494f0001007000000000000100000000000000{}00000100000000000000000000000000{}",
        le_u64(logical.len() as u64),
        payload
    ))?;
    header.extend(hex_bytes(&sha256_bytes(root, &header)?)?);
    header.resize(512, 0);
    let journal = run_dir.join("journal.raw");
    write_len(&journal, 4 * 1024 * 1024)?;
    let mut file = OpenOptions::new().write(true).open(&journal)?;
    file.seek(SeekFrom::Start(512))?;
    file.write_all(&header)?;
    file.seek(SeekFrom::Start(1024))?;
    file.write_all(&logical)?;
    file.sync_all()?;
    fs::copy(&journal, run_dir.join("schema8-negative-journal.raw"))?;
    fs::write(
        run_dir.join("schema8-negative-fixture.txt"),
        format!(
            "nexus.cser.schema8-selected-fixture.v1\nprofile4_source_revision={FIXTURE_REVISION}\nprofile4_source_archive_sha256={FIXTURE_ARCHIVE_SHA256}\nprofile4_catalog_digest={FIXTURE_CATALOG}\nselected_revision=5\nselected_head={FIXTURE_HEAD}\nlogical_journal_sha256={FIXTURE_JOURNAL_SHA256}\n"
        ),
    )?;
    Ok(fs::read(&journal)?)
}

fn run_four_boots(root: &Path, image: &Image, run_dir: &Path, catalog: &str) -> Result<()> {
    let state = run_dir.join("tpmstate");
    status(
        root,
        "bash",
        &[
            script(root, "provision-cser-tpm-nv.sh")?
                .to_str()
                .ok_or("non-utf8 script")?,
            state.to_str().ok_or("non-utf8 state")?,
            catalog,
        ],
    )?;
    for boot in 1..=4 {
        capture(
            root,
            image,
            run_dir,
            &format!("boot{boot}"),
            "cser-production",
            90,
            true,
        )?;
    }
    let mut markers = Vec::new();
    for boot in 1..=4 {
        markers.push(exact_marker(
            &run_dir.join(format!("boot{boot}-serial.log")),
            &format!("CSER_CORE_PERSISTENT_BOOT{boot} PASS"),
            &["shared_runtime=true", "production_registry=single"],
        )?);
    }
    assert_boot_progression(&markers)?;
    assert_boot_semantics(&markers, catalog)?;
    assert_dma_arena(
        &markers[0],
        &markers[2],
        &fs::read_to_string(run_dir.join("boot1-qemu-debug.log"))?,
        &fs::read_to_string(run_dir.join("boot3-qemu-debug.log"))?,
    )?;
    let traces = (1..=4)
        .map(|boot| fs::read_to_string(run_dir.join(format!("boot{boot}-qemu-debug.log"))))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (index, trace) in traces.iter().enumerate() {
        let boot = index + 1;
        if !trace.contains("vtd_inv_desc_iotlb_global") || trace.contains("vtd_dmar_fault") {
            return Err(format!("boot {boot} violates IOTLB/fault predicate").into());
        }
    }
    assert_boot_trace_shape(&traces)?;
    Ok(())
}

fn capture(
    root: &Path,
    image: &Image,
    run_dir: &Path,
    name: &str,
    scheme: &str,
    seconds: u32,
    production_tpm: bool,
) -> Result<()> {
    let serial = format!("/work/target/nexus/system/{name}-serial.log");
    let debug = format!("/work/target/nexus/system/{name}-qemu-debug.log");
    let mut host_tpm = if production_tpm {
        Some(start_swtpm(run_dir)?)
    } else {
        None
    };
    let command = format!(
        "cd /work; cp /root/ovmf/release/OVMF_VARS.fd \"$HOME/OVMF_VARS.fd\"; test \"$(sha256sum /opt/nexus-fixtures/runtime-fs-block.raw | cut -d ' ' -f1)\" = {RUNTIME_FS_SHA256}; source scripts/qemu-stream-capture.sh; capture_qemu_streams {serial} {debug} bash -lc 'timeout --signal=TERM --kill-after=2s {seconds}s cargo osdk run --scheme {scheme}'"
    );
    let runner = root.join(KERNEL).join("target/osdk/nexus-kernel-run-base");
    let runner_before = runner_controls(root, &runner)?;
    let result = container(root, image, &command, production_tpm);
    let runner_result = assert_runner_unchanged(root, &runner, &runner_before);
    let stop_result = host_tpm.as_mut().map(stop_swtpm).transpose();
    result?;
    runner_result?;
    stop_result?;
    Ok(())
}

struct Swtpm {
    child: Child,
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn start_swtpm(run_dir: &Path) -> Result<Swtpm> {
    let socket = run_dir.join("swtpm-qemu.sock");
    let pid = run_dir.join("swtpm.pid");
    let _ = fs::remove_file(&socket);
    let _ = fs::remove_file(&pid);
    let caps = output(run_dir, "swtpm", &["socket", "--print-capabilities"])?;
    let flags = if caps.contains("flags-opt-disable-auto-shutdown") {
        "not-need-init,startup-none,disable-auto-shutdown"
    } else {
        "not-need-init,startup-none"
    };
    let child = Command::new("swtpm")
        .current_dir(run_dir)
        .args([
            "socket",
            "--tpm2",
            "--tpmstate",
            &format!("dir={}", run_dir.join("tpmstate").display()),
            "--ctrl",
            &format!("type=unixio,path={}", socket.display()),
            "--flags",
            flags,
            "--log",
            &format!("file={},level=20", run_dir.join("swtpm.log").display()),
            "--pid",
            &format!("file={}", pid.display()),
        ])
        .spawn()?;
    let mut daemon = Swtpm { child };
    for _ in 0..500 {
        if socket.exists() && pid.exists() {
            return Ok(daemon);
        }
        if daemon.child.try_wait()?.is_some() {
            return Err("persistent swtpm exited before creating its socket".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err("persistent swtpm did not create its socket".into())
}

fn stop_swtpm(tpm: &mut Swtpm) -> Result<()> {
    if tpm.child.try_wait()?.is_none() {
        tpm.child.kill()?;
    }
    tpm.child.wait()?;
    Ok(())
}

fn snapshot_tpm(root: &Path, state: &Path, output_path: &Path) -> Result<String> {
    let work = state.join(".snapshot");
    if work.exists() {
        fs::remove_dir_all(&work)?;
    }
    fs::create_dir(&work)?;
    let socket = work.join("server.sock");
    let pid_file = work.join("swtpm.pid");
    let child = Command::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--tpmstate",
            &format!("dir={}", state.display()),
            "--ctrl",
            &format!("type=unixio,path={}.ctrl", socket.display()),
            "--server",
            &format!("type=unixio,path={}", socket.display()),
            "--flags",
            "not-need-init,startup-clear",
            "--pid",
            &format!("file={}", pid_file.display()),
        ])
        .spawn()?;
    let mut daemon = Swtpm { child };
    for _ in 0..500 {
        if socket.exists() && pid_file.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if !socket.exists() {
        return Err("TPM snapshot daemon did not start".into());
    }
    let tcti = format!("swtpm:path={}", socket.display());
    let coordinates = [
        ("0x01800100", "tip-counter.bin", Some("8")),
        ("0x01800101", "tip-slot-0.bin", None),
        ("0x01800102", "tip-slot-1.bin", None),
        ("0x01800103", "lease-counter.bin", Some("8")),
        ("0x01800104", "lease-slot-0.bin", None),
        ("0x01800105", "lease-slot-1.bin", None),
    ];
    for (index, file, size) in coordinates {
        let output = work.join(file);
        let mut args = vec![
            "-Q",
            "-T",
            &tcti,
            "-C",
            index,
            "-o",
            output.to_str().ok_or("non-utf8 TPM file")?,
            index,
        ];
        if let Some(size) = size {
            args.splice(5..5, ["-s", size]);
        }
        status(root, "tpm2_nvread", &args)?;
    }
    let tip = hex(&fs::read(work.join("tip-counter.bin"))?);
    let lease = hex(&fs::read(work.join("lease-counter.bin"))?);
    let tip_slot = u8::from_str_radix(&tip[14..], 16)? & 1;
    let lease_slot = u8::from_str_radix(&lease[14..], 16)? & 1;
    let selected = [
        format!("0x0180010{}", tip_slot + 1),
        format!("0x0180010{}", lease_slot + 4),
    ];
    let mut snapshot = format!(
        "nexus.cser.schema8-tpm-nv.v2\ntip_counter_hex={tip}\nlease_counter_hex={lease}\ntip_selected_slot={tip_slot}\nlease_selected_slot={lease_slot}\ntip_selected_slot_index={}\nlease_selected_slot_index={}\n",
        selected[0], selected[1]
    );
    for (label, file) in [
        ("tip_slot_0", "tip-slot-0.bin"),
        ("tip_slot_1", "tip-slot-1.bin"),
        ("lease_slot_0", "lease-slot-0.bin"),
        ("lease_slot_1", "lease-slot-1.bin"),
    ] {
        snapshot.push_str(&format!(
            "{label}_sha256={}\n",
            sha256(root, &work.join(file))?
        ));
    }
    snapshot.push_str(&format!(
        "provisioned_nv_digest={}\n",
        sha256_bytes(root, snapshot.as_bytes())?
    ));
    fs::write(output_path, &snapshot)?;
    stop_swtpm(&mut daemon)?;
    fs::remove_dir_all(work)?;
    Ok(snapshot)
}

fn container(root: &Path, image: &Image, command: &str, host_socket: bool) -> Result<()> {
    container_output(root, image, command, host_socket).map(|_| ())
}
fn container_output(
    root: &Path,
    image: &Image,
    command: &str,
    host_socket: bool,
) -> Result<String> {
    let uid = output(root, "id", &["-u"])?.trim().to_string();
    let gid = output(root, "id", &["-g"])?.trim().to_string();
    let repo = root.to_str().ok_or("non-utf8 repository root")?;
    let kernel = root.join(KERNEL);
    let kernel = kernel.to_str().ok_or("non-utf8 kernel root")?;
    let core = root.join("crates/cser-core");
    let core = core.to_str().ok_or("non-utf8 core root")?;
    let model = root.join("crates/cser-model");
    let model = model.to_str().ok_or("non-utf8 model root")?;
    let virtio = root.join("crates/nexus-ostd-virtio");
    let virtio = virtio.to_str().ok_or("non-utf8 virtio root")?;
    let kernel_lock = root.join(KERNEL).join("Cargo.lock");
    let kernel_lock = kernel_lock.to_str().ok_or("non-utf8 kernel lock")?;
    let mut args = vec![
        "run".to_string(),
        "--rm".into(),
        "--init".into(),
        "--platform".into(),
        "linux/amd64".into(),
        "--network".into(),
        "none".into(),
        "--user".into(),
        format!("{uid}:{gid}"),
        "--env".into(),
        "HOME=/tmp/nexus-home".into(),
        "--tmpfs".into(),
        "/tmp/nexus-home:rw,exec,nosuid,size=64m,mode=1777".into(),
        "-v".into(),
        format!("{kernel}:/work:z"),
        "-v".into(),
        format!("{repo}:/repo:ro,z"),
        "-v".into(),
        format!("{core}:/crates/cser-core:ro,z"),
        "-v".into(),
        format!("{model}:/crates/cser-model:ro,z"),
        "-v".into(),
        format!("{virtio}:/crates/nexus-ostd-virtio:ro,z"),
        "--mount".into(),
        format!("type=bind,source={kernel_lock},target=/work/Cargo.lock,readonly"),
        "--workdir".into(),
        "/work".into(),
    ];
    if host_socket {
        args.extend(["--security-opt".into(), "label=disable".into()]);
        if output(
            root,
            "docker",
            &["info", "--format", "{{json .SecurityOptions}}"],
        )?
        .contains("name=apparmor")
        {
            args.extend(["--security-opt".into(), "apparmor=unconfined".into()]);
        }
    }
    args.extend([
        image.reference.clone(),
        "bash".into(),
        "-lc".into(),
        format!("set -eu; {command}"),
    ]);
    command_output(root, "docker", &args)
}

fn exact_marker(path: &Path, prefix: &str, required: &[&str]) -> Result<String> {
    let text = fs::read_to_string(path)?.replace('\r', "");
    let pass = text
        .lines()
        .filter(|line| tokens_match(line, prefix))
        .collect::<Vec<_>>();
    let fail_prefix = prefix
        .strip_suffix(" PASS")
        .map(|value| format!("{value} FAIL"));
    if pass.len() != 1
        || fail_prefix
            .as_ref()
            .is_some_and(|fail| text.lines().any(|line| tokens_match(line, fail)))
    {
        return Err(format!("marker {prefix:?} is not exactly one PASS without FAIL").into());
    }
    let marker = pass[0].to_string();
    for token in required {
        if !has_unique_token(&marker, token) {
            return Err(format!("marker lacks unique token {token}").into());
        }
    }
    Ok(marker)
}
fn require_unique_token(marker: &str, expected: &str) -> Result<()> {
    if !has_unique_token(marker, expected) {
        return Err(format!("marker lacks unique token {expected}").into());
    }
    Ok(())
}
fn has_unique_token(marker: &str, expected: &str) -> bool {
    let exact = marker
        .split_whitespace()
        .filter(|token| *token == expected)
        .count();
    let Some((key, _)) = expected.split_once('=') else {
        return exact == 1;
    };
    let prefix = format!("{key}=");
    exact == 1
        && marker
            .split_whitespace()
            .filter(|token| token.starts_with(&prefix))
            .count()
            == 1
}
fn token_value<'a>(marker: &'a str, field: &str) -> Result<&'a str> {
    let prefix = format!("{field}=");
    let values = marker
        .split_whitespace()
        .filter_map(|token| token.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(format!("marker has invalid {field}").into());
    }
    Ok(values[0])
}
fn tokens_match(line: &str, marker: &str) -> bool {
    let a = line.split_whitespace().collect::<Vec<_>>();
    let b = marker.split_whitespace().collect::<Vec<_>>();
    a.windows(b.len()).any(|part| part == b)
}

fn assert_boot_progression(markers: &[String]) -> Result<()> {
    if markers.len() != 4 {
        return Err("expected exactly four boot markers".into());
    }
    for field in ["revision", "boot", "journal", "device"] {
        let values = markers
            .iter()
            .map(|m| number(m, field))
            .collect::<Result<Vec<_>>>()?;
        if !values.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(format!("{field} is not strictly increasing").into());
        }
    }
    for (index, marker) in markers.iter().enumerate() {
        let expected = index as u64 + 1;
        if number(marker, "executor_generation")? != expected
            || number(marker, "service_executor_generation")? != expected
        {
            return Err("executor generations are not 1,2,3,4".into());
        }
    }
    Ok(())
}

fn assert_boot_semantics(markers: &[String], catalog: &str) -> Result<()> {
    let common = [
        "shared_runtime=true",
        "production_registry=single",
        "api_profile=6",
        "catalog_version=8",
        "projection_version=10",
        "snapshot_version=6",
        "journal_schema=10",
        "production_world=1",
        "reply_provider=1:1:1",
        "dma_provider=1:2:1",
        "operation_id=1",
        "effect_sequence=1",
        "reply_component_id=1",
        "dma_component_id=2",
        "portal=nxp3",
        "supervisor=core-v1",
    ];
    let expected: [&[&str]; 4] = [
        &[
            "profile=6",
            "composite_effect=true",
            "effect_identity=shared",
            "component_ids=reply+dma",
            "reply=committed-unsettled",
            "dma=queue-published-retained",
            "retained=4",
            "dma_retained=3",
            "resource_generation=1",
            "resumed_prefix=false",
            "production_service_tasks=1",
            "service_death=task-return",
            "exact_reap=true",
            "ingress_latch=closed",
            "closed_ingress_rejected=true",
            "production_rebind=initial",
        ],
        &[
            "reply=reconciliation-required",
            "resumed_prefix=true",
            "pre_fence_reply=apply-intent-durable",
            "core_apply_intent_durable=true",
            "second_crash=service-exact-reap",
            "external_apply_durable=false",
            "no_external_apply=true",
            "dma_queue=retired",
            "dma_pages_iova=retired",
            "dma_component=retired",
            "retained=1",
            "dma_retained=0",
            "activation=deferred",
            "resource_reuse_authorized=true",
            "reset_submitted=3",
            "irq_submitted=1",
            "iotlb_submitted=2",
            "fresh_service_task=true",
            "ready_in_fresh_task=true",
            "production_rebind=true",
            "service_death=task-return",
            "exact_reap=true",
            "ingress_latch=closed",
            "closed_ingress_rejected=true",
        ],
        &[
            "reuse_operation_id=1",
            "reuse_effect_sequence=2",
            "reply=settled-after-second-crash",
            "reconciliation=true",
            "second_apply_intent=false",
            "dma=reused-published",
            "retained=3",
            "dma_retained=3",
            "resource_generation=2",
            "prior_resource_generation=1",
            "stale_old_generation_evidence=rejected_without_mutation",
            "activation=active",
            "resource_reuse_authorized=true",
            "exact_guest_pfn_reuse=true",
            "exact_emulated_iova_reuse=true",
            "exact_backing_offset_reuse=true",
            "fresh_service_task=true",
            "ready_in_fresh_task=true",
            "production_rebind=true",
            "service_state=live",
            "ingress_latch=open",
            "prior_service_fence=same-boot-exact-reap",
        ],
        &[
            "reuse_operation_id=1",
            "reuse_effect_sequence=2",
            "reply=settled",
            "repeated_recovery=stable",
            "duplicate_apply_intent=false",
            "duplicate_dma_evidence=false",
            "dma_queue=retired",
            "dma_pages_iova=retired",
            "retained=0",
            "dma_retained=0",
            "activation=deferred",
            "resource_reuse_authorized=true",
            "reset_submitted=3",
            "irq_submitted=1",
            "iotlb_submitted=2",
            "fresh_service_task=true",
            "ready_in_fresh_task=true",
            "production_rebind=true",
            "service_state=live",
            "ingress_latch=open",
            "prior_service_fence=boot-checkpoint",
        ],
    ];
    let mut projections = Vec::new();
    for (index, marker) in markers.iter().enumerate() {
        for token in common.iter().chain(expected[index].iter()) {
            require_unique_token(marker, token)?;
        }
        require_unique_token(marker, &format!("catalog_set_digest={catalog}"))?;
        let projection = token_value(marker, "projection_digest")?;
        if !valid_hex(projection, 64) {
            return Err("boot projection digest is malformed".into());
        }
        projections.push(projection.to_owned());
    }
    if projections.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("persistent boots reused a projection digest".into());
    }
    let one = token_value(&markers[0], "arena_contract_digest")?;
    let three = token_value(&markers[2], "arena_contract_digest")?;
    if !valid_hex(one, 64) || one != three {
        return Err("DMA reuse did not retain one exact arena contract".into());
    }
    Ok(())
}

fn assert_boot_trace_shape(traces: &[String]) -> Result<()> {
    if traces.len() != 4 {
        return Err("expected four boot traces".into());
    }
    let count = |trace: &str, prefix: &str| {
        trace
            .lines()
            .filter(|line| line.starts_with(prefix))
            .count()
    };
    let events = [
        "virtio_queue_notify ",
        "virtio_pci_notify_write ",
        "virtio_blk_handle_read ",
    ];
    for event in events {
        let values = traces
            .iter()
            .map(|trace| count(trace, event))
            .collect::<Vec<_>>();
        if values[1] == 0
            || values[1] != values[3]
            || values[0] != values[1] + 1
            || values[2] != values[1] + 1
        {
            return Err(format!("four boots violate the stable {event} trace baseline").into());
        }
    }
    let translations = traces
        .iter()
        .map(|trace| count(trace, "vtd_dmar_translate dev 00:05.00 "))
        .collect::<Vec<_>>();
    if translations[0] == 0 || translations[2] == 0 || translations[1] != 0 || translations[3] != 0
    {
        return Err(
            "recovery-only boot emitted or publication boot lacked DMA translations".into(),
        );
    }
    Ok(())
}
fn assert_dma_arena(one: &str, three: &str, trace_one: &str, trace_three: &str) -> Result<()> {
    if number(one, "resource_generation")? != 1 || number(three, "resource_generation")? != 2 {
        return Err("DMA resource generation did not advance 1 to 2".into());
    }
    for field in [
        "guest_pfn_base",
        "emulated_iova_base",
        "host_backing_offset",
    ] {
        if number(one, field)? != number(three, field)? {
            return Err(format!("DMA arena {field} changed across reuse").into());
        }
    }
    let pfn = number(one, "guest_pfn_base")?;
    let iova = number(one, "emulated_iova_base")?;
    let offset = number(one, "host_backing_offset")?;
    const PAGE: u64 = 4096;
    const PAGES: u64 = 3;
    const RAM: u64 = 1024 * 1024 * 1024;
    if offset / PAGE != pfn || iova % PAGE != 0 || offset % PAGE != 0 || offset > RAM - PAGES * PAGE
    {
        return Err("DMA arena coordinates are not a bounded aligned PFN range".into());
    }
    for trace in [trace_one, trace_three] {
        if trace.contains("vtd_dmar_fault") || trace.contains("0xffff") {
            return Err("DMA arena trace lacks exact safe translation evidence".into());
        }
        for page in 0..PAGES {
            let expected = format!(
                "vtd_dmar_translate dev 00:05.00 iova 0x{:x} -> gpa 0x{:x} mask 0xfff",
                iova + page * PAGE,
                offset + page * PAGE
            );
            let related = trace
                .lines()
                .filter(|line| {
                    line.starts_with("vtd_dmar_translate dev 00:05.00")
                        && line.split_whitespace().nth(4)
                            == Some(&format!("0x{:x}", iova + page * PAGE))
                })
                .collect::<Vec<_>>();
            if related.is_empty() || related.iter().any(|line| **line != expected) {
                return Err("DMA arena trace has a missing or conflicting exact mapping".into());
            }
        }
    }
    Ok(())
}
fn assert_schema8_trace(trace: &str, marker: &str) -> Result<()> {
    for token in [
        "bus_master_disabled=true",
        "intx_masked=true",
        "reset_status_zero=true",
        "observed_isr_bits=0",
        "iotlb_used_remapped_iova=true",
    ] {
        require_unique_token(marker, token)?;
    }
    if number(marker, "isr_reads")? < 2
        || number(marker, "consecutive_empty_isr_reads")? != 2
        || number(marker, "iotlb_completed_trigger_pages")? < 1
    {
        return Err("schema8 marker lacks terminal ISR/IOTLB observations".into());
    }
    const WRITE: &str = "pci_cfg_write virtio-blk-pci 00:05.0 @0x4 <- ";
    const READ: &str = "pci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> ";
    let lines = trace.lines().collect::<Vec<_>>();
    let quarantined = |command: u64| command & 4 == 0 && command & 0x400 != 0;
    let command = |line: &str, prefix: &str| {
        line.strip_prefix(prefix)
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.strip_prefix("0x"))
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            .map(|value| value & 0xffff)
    };
    if lines.iter().any(|line| line.starts_with("vtd_dmar_fault")) {
        return Err("schema8 trace contains a VT-d fault".into());
    }
    let boot_fence = |command: u64| (command | 2 | 0x400) & !4;
    let mut previous_read = None;
    let mut candidates = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if let Some(value) = command(line, READ) {
            previous_read = Some(value);
        } else if let Some(value) = command(line, WRITE)
            && previous_read
                .take()
                .is_some_and(|previous| value == boot_fence(previous))
        {
            candidates.push((index, value));
        }
    }
    let valid = candidates.into_iter().any(|(fence, fence_command)| {
        let Some((readback, is_read, readback_command)) = lines
            .iter()
            .enumerate()
            .skip(fence + 1)
            .find_map(|(index, line)| {
                command(line, READ)
                    .map(|value| (index, true, value))
                    .or_else(|| command(line, WRITE).map(|value| (index, false, value)))
            })
        else {
            return false;
        };
        if !is_read || readback_command != fence_command || !quarantined(readback_command) {
            return false;
        }
        let Some((reset, reset_line)) = lines
            .iter()
            .enumerate()
            .skip(readback + 1)
            .find(|(_, line)| line.starts_with("virtio_set_status"))
        else {
            return false;
        };
        if !reset_line.starts_with("virtio_set_status vdev ") || !reset_line.ends_with(" val 0") {
            return false;
        }
        let Some(iotlb) = lines
            .iter()
            .enumerate()
            .skip(reset + 1)
            .find(|(_, line)| *line == &"vtd_inv_desc_iotlb_global iotlb invalidate global")
            .map(|(index, _)| index)
        else {
            return false;
        };
        let Some(wait) = lines
            .iter()
            .enumerate()
            .skip(iotlb + 1)
            .find(|(_, line)| {
                *line == &"vtd_inv_desc_wait_irq IM in IECTL_REG is set, new event not generated"
            })
            .map(|(index, _)| index)
        else {
            return false;
        };
        let bad_command = lines[fence..].iter().any(|line| {
            command(line, WRITE)
                .or_else(|| command(line, READ))
                .is_some_and(|value| !quarantined(value))
        });
        let bad_after_iotlb = lines[iotlb..].iter().any(|line| {
            line.starts_with("virtio_queue_notify")
                || line.starts_with("virtio_pci_notify_write")
                || line.starts_with("virtio_notify")
                || line.starts_with("vtd_dmar_translate dev 00:05.00")
                || line.starts_with("virtio_set_status") && !line.ends_with(" val 0")
        });
        fence < readback
            && readback < reset
            && reset < iotlb
            && iotlb < wait
            && !bad_command
            && !bad_after_iotlb
    });
    if !valid {
        return Err("schema8 trace violates quarantine ordering".into());
    }
    Ok(())
}

#[cfg(test)]
fn exact_marker_from(text: &str, prefix: &str, tokens: &[&str]) -> Option<()> {
    let found = text
        .lines()
        .filter(|l| tokens_match(l, prefix))
        .collect::<Vec<_>>();
    (found.len() == 1
        && tokens.iter().all(|token| has_unique_token(found[0], token))
        && !text.contains(&prefix.replacen(" PASS", " FAIL", 1)))
    .then_some(())
}
fn number(marker: &str, field: &str) -> Result<u64> {
    let values = marker
        .split_whitespace()
        .filter_map(|token| token.strip_prefix(&format!("{field}=")))
        .collect::<Vec<_>>();
    if values.len() != 1 || !values[0].bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("invalid {field}").into());
    }
    Ok(values[0].parse()?)
}

fn script(root: &Path, name: &str) -> Result<PathBuf> {
    let path = root.join(KERNEL).join("scripts").join(name);
    if !path.is_file() || fs::symlink_metadata(&path)?.file_type().is_symlink() {
        return Err(format!(
            "required leaf script is missing or unsafe: {}",
            path.display()
        )
        .into());
    }
    Ok(path)
}
fn system_output(root: &Path) -> PathBuf {
    root.join(SYSTEM_OUTPUT)
}
fn write_len(path: &Path, length: u64) -> Result<()> {
    let file = File::create(path)?;
    file.set_len(length)?;
    Ok(())
}
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(format!(
                "controlled runner source contains a symlink: {}",
                entry.path().display()
            )
            .into());
        }
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target)?;
        } else {
            return Err("controlled runner source has an unsupported entry".into());
        }
    }
    Ok(())
}
fn runner_controls(root: &Path, runner: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    for relative in ["Cargo.toml", "Cargo.lock", "src/main.rs"] {
        let path = runner.join(relative);
        bytes.extend_from_slice(relative.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(sha256(root, &path)?.as_bytes());
        bytes.push(0);
    }
    sha256_bytes(root, &bytes)
}
fn sha256(root: &Path, path: &Path) -> Result<String> {
    let path = path.to_str().ok_or("non-utf8 hash input")?;
    let line = output(root, "sha256sum", &[path])?;
    let digest = line
        .split_whitespace()
        .next()
        .ok_or("sha256sum returned no digest")?
        .to_string();
    if !valid_hex(&digest, 64) {
        return Err("sha256sum returned malformed digest".into());
    }
    Ok(digest)
}
fn sha256_bytes(root: &Path, bytes: &[u8]) -> Result<String> {
    let mut child = Command::new("sha256sum")
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or("sha256sum stdin unavailable")?
        .write_all(bytes)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err("sha256sum failed".into());
    }
    let digest = String::from_utf8(out.stdout)?
        .split_whitespace()
        .next()
        .ok_or("sha256sum returned no digest")?
        .to_string();
    if !valid_hex(&digest, 64) {
        return Err("sha256sum returned malformed digest".into());
    }
    Ok(digest)
}
fn le_u64(value: u64) -> String {
    value
        .to_le_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn hex_bytes(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("malformed hex".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16).map_err(|e| Box::new(e) as Box<dyn Error>)
        })
        .collect()
}
fn valid_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn valid_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7) || b.is_ascii_digit())
}
fn status(root: &Path, program: &str, args: &[&str]) -> Result<()> {
    command_output(
        root,
        program,
        &args.iter().map(|x| (*x).to_string()).collect::<Vec<_>>(),
    )
    .map(|_| ())
}
fn output(root: &Path, program: &str, args: &[&str]) -> Result<String> {
    command_output(
        root,
        program,
        &args.iter().map(|x| (*x).to_string()).collect::<Vec<_>>(),
    )
}
fn command_output(root: &Path, program: &str, args: &[String]) -> Result<String> {
    let result = Command::new(program)
        .current_dir(root)
        .args(args)
        .output()?;
    if !result.status.success() {
        return Err(format!(
            "{program} failed with {}:\nstdout:\n{}\nstderr:\n{}",
            result.status,
            String::from_utf8_lossy(&result.stdout).trim(),
            String::from_utf8_lossy(&result.stderr).trim()
        )
        .into());
    }
    let mut combined = String::from_utf8(result.stdout)?;
    combined.push_str(&String::from_utf8(result.stderr)?);
    Ok(combined)
}

fn tpm_snapshot_unchanged(before: &str, after: &str) -> bool {
    let valid = |snapshot: &str| {
        let field = |name: &str| {
            let prefix = format!("{name}=");
            let values = snapshot
                .lines()
                .filter_map(|line| line.strip_prefix(&prefix))
                .collect::<Vec<_>>();
            (values.len() == 1).then_some(values[0])
        };
        snapshot.lines().next() == Some("nexus.cser.schema8-tpm-nv.v2")
            && field("tip_counter_hex").is_some_and(|value| valid_hex(value, 16))
            && field("lease_counter_hex").is_some_and(|value| valid_hex(value, 16))
            && field("tip_selected_slot").is_some_and(|value| matches!(value, "0" | "1"))
            && field("lease_selected_slot").is_some_and(|value| matches!(value, "0" | "1"))
            && field("tip_selected_slot_index")
                .is_some_and(|value| matches!(value, "0x01800101" | "0x01800102"))
            && field("lease_selected_slot_index")
                .is_some_and(|value| matches!(value, "0x01800104" | "0x01800105"))
            && field("tip_slot_0_sha256").is_some_and(|value| valid_hex(value, 64))
            && field("tip_slot_1_sha256").is_some_and(|value| valid_hex(value, 64))
            && field("lease_slot_0_sha256").is_some_and(|value| valid_hex(value, 64))
            && field("lease_slot_1_sha256").is_some_and(|value| valid_hex(value, 64))
            && field("provisioned_nv_digest").is_some_and(|value| valid_hex(value, 64))
    };
    valid(before) && valid(after) && before == after
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA_MARKER: &str = "X bus_master_disabled=true intx_masked=true reset_status_zero=true observed_isr_bits=0 isr_reads=2 consecutive_empty_isr_reads=2 iotlb_used_remapped_iova=true iotlb_completed_trigger_pages=1";
    const SAFE_TRACE: &str = "pci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> 0x100007\npci_cfg_write virtio-blk-pci 00:05.0 @0x4 <- 0x403\npci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> 0x100403\nvirtio_set_status vdev 0x1 val 0\nvtd_inv_desc_iotlb_global iotlb invalidate global\nvtd_inv_desc_wait_irq IM in IECTL_REG is set, new event not generated";

    #[test]
    fn command_failure_reports_stdout_and_stderr() {
        let error = command_output(
            Path::new("."),
            "sh",
            &[
                "-c".into(),
                "printf guest-progress; printf guest-error >&2; exit 7".into(),
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("stdout:\nguest-progress"));
        assert!(error.contains("stderr:\nguest-error"));
    }

    #[test]
    fn marker_rejects_wrong_duplicate_and_conflicting_results() {
        assert!(exact_marker_from("X PASS key=value", "X PASS", &["key=value"]).is_some());
        assert!(exact_marker_from("X PASS key=other", "X PASS", &["key=value"]).is_none());
        assert!(
            exact_marker_from("X PASS key=value key=value", "X PASS", &["key=value"]).is_none()
        );
        assert!(
            exact_marker_from("X PASS key=value key=other", "X PASS", &["key=value"]).is_none()
        );
        assert!(
            exact_marker_from(
                "X PASS key=value\nX PASS key=value",
                "X PASS",
                &["key=value"]
            )
            .is_none()
        );
        assert!(exact_marker_from("X PASS key=value\nX FAIL", "X PASS", &["key=value"]).is_none());
    }

    #[test]
    fn focused_dma_accepts_only_pre_escape_unsupported_closure() {
        let unsupported = "CSER_CORE_DMA_IRQ UNSUPPORTED outcome=FAIL_CLOSED reason=controller_pending_synchronization_unsupported pci_intx_masked=true queue_published=false request_owner_created=false irq_mapping_retained=true qemu_evidence=false physical_hardware_evidence=false";
        assert!(assert_dma_irq_unsupported(unsupported, "").is_ok());
        assert!(
            assert_dma_irq_unsupported(
                &format!("{unsupported}\nCSER_CORE_DMA HardwareClosure PASS"),
                ""
            )
            .is_err()
        );
        assert!(assert_dma_irq_unsupported(unsupported, "virtio_pci_notify_write").is_err());
        assert!(assert_dma_irq_unsupported(unsupported, "virtio_blk_handle_read").is_err());
        assert!(
            assert_dma_irq_unsupported("CSER_CORE_DMA_IRQ UNSUPPORTED outcome=FAIL_CLOSED", "")
                .is_err()
        );
    }

    #[test]
    fn schema8_rejects_missing_readback_bus_master_and_post_iotlb_notify() {
        assert!(assert_schema8_trace(SAFE_TRACE, SCHEMA_MARKER).is_ok());
        assert!(assert_schema8_trace(
            "pci_cfg_write virtio-blk-pci 00:05.0 @0x4 <- 0x403\nvirtio_set_status vdev 0x1 val 0\nvtd_inv_desc_iotlb_global iotlb invalidate global\nvtd_inv_desc_wait_irq IM in IECTL_REG is set, new event not generated",
            SCHEMA_MARKER
        )
        .is_err());
        assert!(assert_schema8_trace("pci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> 0x100007\npci_cfg_write virtio-blk-pci 00:05.0 @0x4 <- 0x403\npci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> 0x100403\nvirtio_set_status vdev 0x1 val 0\nvtd_inv_desc_iotlb_global iotlb invalidate global\npci_cfg_write virtio-blk-pci 00:05.0 @0x4 <- 0x404\nvtd_inv_desc_wait_irq IM in IECTL_REG is set, new event not generated", SCHEMA_MARKER).is_err());
        assert!(assert_schema8_trace("pci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> 0x100007\npci_cfg_write virtio-blk-pci 00:05.0 @0x4 <- 0x403\npci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> 0x100403\nvirtio_set_status vdev 0x1 val 0\nvtd_dmar_fault\nvtd_inv_desc_iotlb_global iotlb invalidate global\nvtd_inv_desc_wait_irq IM in IECTL_REG is set, new event not generated", SCHEMA_MARKER).is_err());
        assert!(assert_schema8_trace("pci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> 0x100007\npci_cfg_write virtio-blk-pci 00:05.0 @0x4 <- 0x403\npci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> 0x100403\nvirtio_set_status vdev 0x1 val 0\nvtd_inv_desc_iotlb_global iotlb invalidate global\nvirtio_queue_notify\nvtd_inv_desc_wait_irq IM in IECTL_REG is set, new event not generated", SCHEMA_MARKER).is_err());
        assert!(assert_schema8_trace("pci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> 0x100007\npci_cfg_write virtio-blk-pci 00:05.0 @0x4 <- 0x7\npci_cfg_write virtio-blk-pci 00:05.0 @0x4 <- 0x403\npci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> 0x100403\nvirtio_set_status vdev 0x1 val 0\nvtd_inv_desc_iotlb_global iotlb invalidate global\nvtd_inv_desc_wait_irq IM in IECTL_REG is set, new event not generated", SCHEMA_MARKER).is_err());
        assert!(assert_schema8_trace("pci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> 0x100007\npci_cfg_write virtio-blk-pci 00:05.0 @0x4 <- 0x403\npci_cfg_write virtio-blk-pci 00:05.0 @0x4 <- 0x400\npci_cfg_read virtio-blk-pci 00:05.0 @0x4 -> 0x100403\nvirtio_set_status vdev 0x1 val 0\nvtd_inv_desc_iotlb_global iotlb invalidate global\nvtd_inv_desc_wait_irq IM in IECTL_REG is set, new event not generated", SCHEMA_MARKER).is_err());
    }

    #[test]
    fn schema8_rejects_tpm_coordinate_change() {
        let before = "nexus.cser.schema8-tpm-nv.v2\ntip_counter_hex=0000000000000001\nlease_counter_hex=0000000000000001\ntip_selected_slot=1\nlease_selected_slot=1\ntip_selected_slot_index=0x01800102\nlease_selected_slot_index=0x01800105\ntip_slot_0_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\ntip_slot_1_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nlease_slot_0_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\nlease_slot_1_sha256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\nprovisioned_nv_digest=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n";
        let after = before.replacen("aaaaaaaa", "ffffffff", 1);
        assert!(tpm_snapshot_unchanged(before, before));
        assert!(!tpm_snapshot_unchanged(before, &after));
    }

    #[test]
    fn dma_rejects_conflicting_gpa_wide_mask_and_overflow() {
        let one = "X resource_generation=1 guest_pfn_base=1 emulated_iova_base=4096 host_backing_offset=4096";
        let three = "X resource_generation=2 guest_pfn_base=1 emulated_iova_base=4096 host_backing_offset=4096";
        let trace = "vtd_dmar_translate dev 00:05.00 iova 0x1000 -> gpa 0x1000 mask 0xfff\nvtd_dmar_translate dev 00:05.00 iova 0x2000 -> gpa 0x2000 mask 0xfff\nvtd_dmar_translate dev 00:05.00 iova 0x3000 -> gpa 0x3000 mask 0xfff";
        assert!(assert_dma_arena(one, three, trace, trace).is_ok());
        assert!(assert_dma_arena(
            one,
            "X resource_generation=2 guest_pfn_base=9 emulated_iova_base=4096 host_backing_offset=4096",
            trace,
            trace
        )
        .is_err());
        assert!(
            assert_dma_arena(one, three, &trace.replacen("0xfff", "0xffff", 1), trace).is_err()
        );
        assert!(assert_dma_arena("X resource_generation=18446744073709551617 guest_pfn_base=1 emulated_iova_base=4096 host_backing_offset=4096", three, trace, trace).is_err());
    }
}
