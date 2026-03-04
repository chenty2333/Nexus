use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

fn default_timeout_ms() -> u64 {
    30_000
}

/// Declarative scenario contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioSpec {
    /// Stable scenario id, used by selection/replay/reporting.
    pub id: String,
    /// Optional short description for human readers.
    #[serde(default)]
    pub description: String,
    /// Free-form labels such as `module:port` or `tier:quick`.
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

/// Selection rules for a named profile.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileSpec {
    /// Keep scenarios that contain at least one tag from this set.
    #[serde(default)]
    pub include_tags: Vec<String>,
    /// Remove scenarios that contain any tag from this set.
    #[serde(default)]
    pub exclude_tags: Vec<String>,
    /// Force include these scenario ids.
    #[serde(default)]
    pub include_ids: Vec<String>,
    /// Force exclude these scenario ids.
    #[serde(default)]
    pub exclude_ids: Vec<String>,
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

/// Load named profile from `<profiles_root>/<name>.toml`.
pub fn load_profile(profiles_root: &Path, name: &str) -> Result<ProfileSpec> {
    let path = profiles_root.join(format!("{name}.toml"));
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read profile file {}", path.display()))?;
    let profile: ProfileSpec =
        toml::from_str(&raw).with_context(|| format!("parse profile file {}", path.display()))?;
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_tag_match_helpers_work() {
        let s = ScenarioSpec {
            id: "x".into(),
            description: String::new(),
            tags: vec!["module:port".into(), "tier:quick".into()],
            timeout_ms: 100,
            command: vec!["echo".into(), "ok".into()],
            expect: vec![],
            forbid: vec![],
        };

        assert!(s.has_all_tags(&["module:port".into()]));
        assert!(s.has_any_tag(&["tier:quick".into(), "tier:slow".into()]));
        assert!(!s.has_all_tags(&["module:timer".into()]));
    }
}
