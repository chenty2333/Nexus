use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

fn default_timeout_ms() -> u64 {
    30_000
}

/// Optional ELF-level assertions for binary boot contracts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ElfCheckSpec {
    /// Path relative to workspace root.
    pub path: String,
    /// Require Xen PVH entry note (type 18) to be present.
    #[serde(default)]
    pub require_xen_pvh_note: bool,
}

/// Structured assertions over parsed key=value metrics from run logs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AssertionsSpec {
    /// Success-path status-like values.
    #[serde(default)]
    pub status_code: BTreeMap<String, i64>,
    /// Error-code values.
    #[serde(default)]
    pub error_code: BTreeMap<String, i64>,
    /// Signal-mask values.
    #[serde(default)]
    pub signal_mask: BTreeMap<String, i64>,
    /// Packet field values.
    #[serde(default)]
    pub packet_fields: BTreeMap<String, i64>,
}

/// Declarative scenario contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioSpec {
    /// Stable scenario id, used by selection/replay/reporting.
    pub id: String,
    /// Optional short description for human readers.
    #[serde(default)]
    pub description: String,
    /// Free-form labels such as `module:port` or `kind:qemu`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Per-scenario timeout budget.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Command vector, first element is executable.
    pub command: Vec<String>,
    /// Tokens that must appear in stdout/stderr concatenation.
    #[serde(default)]
    pub expect: Vec<String>,
    /// Tokens that must not appear in stdout/stderr concatenation.
    #[serde(default)]
    pub forbid: Vec<String>,
    /// Mapped contract ids covered by this scenario.
    #[serde(default)]
    pub contracts: Vec<String>,
    /// Optional structured assertions.
    #[serde(default)]
    pub assertions: Option<AssertionsSpec>,
    /// Optional ELF contract checks.
    #[serde(default)]
    pub elf_check: Option<ElfCheckSpec>,
}

impl ScenarioSpec {
    /// Validate required fields and basic invariants.
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            bail!("scenario id cannot be empty");
        }
        if self.command.is_empty() {
            bail!("scenario '{}' has empty command", self.id);
        }
        if self.timeout_ms == 0 {
            bail!("scenario '{}' timeout_ms must be > 0", self.id);
        }
        if self.contracts.iter().any(|c| c.trim().is_empty()) {
            bail!("scenario '{}' has empty contract id", self.id);
        }
        if let Some(elf_check) = &self.elf_check
            && elf_check.path.trim().is_empty()
        {
            bail!("scenario '{}' has empty elf_check.path", self.id);
        }
        Ok(())
    }

    /// Whether this scenario contains every required tag.
    pub fn has_all_tags(&self, required: &[String]) -> bool {
        required
            .iter()
            .all(|tag| self.tags.iter().any(|t| t == tag))
    }

    /// Whether this scenario contains any tag from candidates.
    pub fn has_any_tag(&self, candidates: &[String]) -> bool {
        candidates
            .iter()
            .any(|tag| self.tags.iter().any(|scenario_tag| scenario_tag == tag))
    }
}

fn collect_toml_files(root: &Path) -> Result<Vec<PathBuf>> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
            let entry = entry.with_context(|| format!("read_dir entry {}", dir.display()))?;
            let path = entry.path();
            let ft = entry
                .file_type()
                .with_context(|| format!("file_type {}", path.display()))?;
            if ft.is_dir() {
                walk(&path, out)?;
            } else if ft.is_file() && path.extension().is_some_and(|ext| ext == "toml") {
                out.push(path);
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    if root.exists() {
        walk(root, &mut files)?;
    }
    files.sort();
    Ok(files)
}

/// Load all scenarios under `root` recursively.
pub fn load_scenarios(root: &Path) -> Result<BTreeMap<String, ScenarioSpec>> {
    if !root.exists() {
        bail!("scenario directory does not exist: {}", root.display());
    }

    let mut out = BTreeMap::new();
    for file in collect_toml_files(root)? {
        let raw = fs::read_to_string(&file)
            .with_context(|| format!("read scenario file {}", file.display()))?;
        let scenario: ScenarioSpec = toml::from_str(&raw)
            .with_context(|| format!("parse scenario file {}", file.display()))?;
        scenario.validate()?;
        if out.insert(scenario.id.clone(), scenario).is_some() {
            return Err(anyhow!("duplicate scenario id in {}", file.display()));
        }
    }

    if out.is_empty() {
        bail!("no scenarios found under {}", root.display());
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_tag_match_helpers_work() {
        let s = ScenarioSpec {
            id: "x".into(),
            description: String::new(),
            tags: vec!["module:port".into(), "kind:qemu".into()],
            timeout_ms: 100,
            command: vec!["echo".into(), "ok".into()],
            expect: vec![],
            forbid: vec![],
            contracts: vec![],
            assertions: None,
            elf_check: None,
        };

        assert!(s.has_all_tags(&["module:port".into()]));
        assert!(s.has_any_tag(&["kind:qemu".into(), "kind:host".into()]));
        assert!(!s.has_all_tags(&["module:timer".into()]));
    }
}
