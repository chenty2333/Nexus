use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};

/// Prune old run directories so at most `keep_runs` remain.
pub fn prune_runs(base_dir: &Path, keep_runs: usize) -> Result<Vec<PathBuf>> {
    if keep_runs == 0 {
        return Ok(Vec::new());
    }
    if !base_dir.exists() {
        return Ok(Vec::new());
    }

    let mut dirs = Vec::new();
    for entry in
        fs::read_dir(base_dir).with_context(|| format!("read_dir {}", base_dir.display()))?
    {
        let entry = entry.with_context(|| format!("read_dir entry {}", base_dir.display()))?;
        let path = entry.path();
        if !entry
            .file_type()
            .with_context(|| format!("file_type {}", path.display()))?
            .is_dir()
        {
            continue;
        }

        let modified = entry
            .metadata()
            .with_context(|| format!("metadata {}", path.display()))?
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH);

        dirs.push((path, modified));
    }

    if dirs.len() <= keep_runs {
        return Ok(Vec::new());
    }

    dirs.sort_by(|(path_a, modified_a), (path_b, modified_b)| {
        modified_a.cmp(modified_b).then_with(|| path_a.cmp(path_b))
    });
    let to_remove = dirs.len() - keep_runs;

    let mut removed = Vec::with_capacity(to_remove);
    for (path, _) in dirs.into_iter().take(to_remove) {
        fs::remove_dir_all(&path).with_context(|| format!("remove_dir_all {}", path.display()))?;
        removed.push(path);
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_respects_keep_limit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path();

        fs::create_dir(base.join("a")).expect("mkdir a");
        std::thread::sleep(std::time::Duration::from_millis(2));
        fs::create_dir(base.join("b")).expect("mkdir b");
        std::thread::sleep(std::time::Duration::from_millis(2));
        fs::create_dir(base.join("c")).expect("mkdir c");

        let removed = prune_runs(base, 2).expect("prune");
        assert_eq!(removed.len(), 1);
        let remaining = ["a", "b", "c"]
            .iter()
            .filter(|name| base.join(name).exists())
            .count();
        assert_eq!(remaining, 2);
    }
}
