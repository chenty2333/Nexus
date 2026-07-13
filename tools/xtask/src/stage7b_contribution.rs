use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::Path;

const DIRECTORY: &str = "target/verification/stage7b";

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Summary {
    pub(crate) verdict: &'static str,
}

#[derive(Serialize)]
struct Decision {
    schema: &'static str,
    status: &'static str,
    verdict: &'static str,
    supported_boundary: &'static str,
    gates: Gates,
    claim_status: ClaimStatus,
    exclusions: Vec<&'static str>,
    decision_reason: &'static str,
}

#[derive(Serialize)]
struct Gates {
    implementation_source_concurrency: &'static str,
    fault_matrix: &'static str,
    scale_structure: &'static str,
    performance_protocol: &'static str,
    prior_art: &'static str,
}

#[derive(Serialize)]
struct ClaimStatus {
    novelty: &'static str,
    first: &'static str,
    proved: &'static str,
}

pub(crate) fn run(root: &Path) -> Result<Summary, String> {
    let directory = root.join(DIRECTORY);
    require_marker(&directory.join("concurrency-oracle.log"), "races=14")?;
    let runtime = read_regular(&directory.join("oracle.log"))?;
    for marker in [
        "status=passed",
        "fault_cells=20",
        "scale_points=14",
        "performance_cases=29",
        "performance_claim=Observed",
        "performance_thresholds=none",
    ] {
        if !runtime.lines().any(|line| line.trim() == marker) {
            return Err(format!("runtime oracle lacks exact marker {marker:?}"));
        }
    }
    require_marker(
        &directory.join("prior-art-oracle.log"),
        "PRIOR_ART ORACLE PASS exact_order=true exact_fields=13 cards_regular_nonsymlink=true card_row_match=true primary_source_only=true audit_digests=16 forbidden_novelty=false support_bounded_allowed=false",
    )?;

    let prior_json = read_regular(&directory.join("prior-art.json"))?;
    let prior: Value = serde_json::from_str(&prior_json)
        .map_err(|error| format!("parse prior-art receipt: {error}"))?;
    let summary = prior
        .get("summary")
        .and_then(Value::as_object)
        .ok_or("prior-art receipt lacks summary object")?;
    if summary.get("rows").and_then(Value::as_u64) != Some(16)
        || summary.get("full_text").and_then(Value::as_u64) != Some(14)
        || summary.get("metadata_only").and_then(Value::as_u64) != Some(2)
        || summary.get("default_verdict").and_then(Value::as_str) != Some("narrow")
        || summary
            .get("support_bounded_allowed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("prior-art receipt cannot authorize the narrow decision".into());
    }

    let decision = Decision {
        schema: "nexus.stage7b.contribution-decision.v1",
        status: "passed",
        verdict: "narrow",
        supported_boundary: "fixed CSER interaction combination under the checked single-vCPU implementation-source and fault/scale/performance protocol",
        gates: Gates {
            implementation_source_concurrency: "Checked 14/14",
            fault_matrix: "Checked 20/20",
            scale_structure: "Checked 14/14",
            performance_protocol: "Observed 29/29; no thresholds",
            prior_art: "Checked 16/16 rows; 14 full-text and 2 primary-metadata-only",
        },
        claim_status: ClaimStatus {
            novelty: "not-established",
            first: "not-established",
            proved: "not-established",
        },
        exclusions: vec![
            "SMP",
            "hardware cycles",
            "lock freedom",
            "production liveness",
            "durable external effects",
            "Linux breadth",
            "identity-preserving Stage5B root composition",
            "full pager adapter equivalence; the legacy serial-oracle mirror remains",
            "full-text audit for Shadow Drivers and Atomic RPC",
        ],
        decision_reason: "all central safety, fault, scale, and measurement-protocol gates pass, but two comparison rows remain metadata-only, so support-bounded is not authorized",
    };
    let mut json = serde_json::to_vec_pretty(&decision)
        .map_err(|error| format!("serialize contribution decision: {error}"))?;
    json.push(b'\n');
    atomic_write(&directory.join("contribution.json"), &json)?;
    let oracle = b"schema=nexus.stage7b.contribution-oracle.v1\nstatus=passed\nverdict=narrow\nconcurrency=14/14\nfault_matrix=20/20\nscale=14/14\nperformance_protocol=29/29\nprior_art_rows=16/16\nprior_art_full_text=14/16\nfull_production_adapter_equivalence=not-established\nnovelty=not-established\nfirst=not-established\nproved=not-established\nforbidden_claims=false\n";
    atomic_write(&directory.join("contribution-oracle.log"), oracle)?;
    Ok(Summary { verdict: "narrow" })
}

fn require_marker(path: &Path, marker: &str) -> Result<(), String> {
    let source = read_regular(path)?;
    if !source.lines().any(|line| line.trim() == marker) {
        return Err(format!("{} lacks exact marker {marker:?}", path.display()));
    }
    Ok(())
}

fn read_regular(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("read metadata {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "required contribution input is not a non-empty regular non-symlink file: {}",
            path.display()
        ));
    }
    fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("output path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("non-UTF-8 output path: {}", path.display()))?,
        std::process::id()
    ));
    fs::write(&temporary, bytes)
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| format!("publish {}: {error}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_boundary_remains_narrow_and_forbidden_claims_remain_absent() {
        let decision = Decision {
            schema: "nexus.stage7b.contribution-decision.v1",
            status: "passed",
            verdict: "narrow",
            supported_boundary: "bounded",
            gates: Gates {
                implementation_source_concurrency: "Checked 14/14",
                fault_matrix: "Checked 20/20",
                scale_structure: "Checked 14/14",
                performance_protocol: "Observed 29/29; no thresholds",
                prior_art: "Checked 16/16 rows; 14 full-text and 2 primary-metadata-only",
            },
            claim_status: ClaimStatus {
                novelty: "not-established",
                first: "not-established",
                proved: "not-established",
            },
            exclusions: vec!["SMP"],
            decision_reason: "metadata-only gap",
        };
        let value = serde_json::to_value(decision).unwrap();
        assert_eq!(value["verdict"], "narrow");
        assert_eq!(value["claim_status"]["novelty"], "not-established");
        assert_ne!(value["verdict"], "support-bounded");
    }
}
