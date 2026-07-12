mod capture;
mod execution;
mod schema;
#[cfg(test)]
mod tests;
mod validation;

use std::path::Path;

pub(crate) fn validate_all(root: &Path) -> Result<usize, String> {
    let scenarios = validation::load_all(root)?;
    Ok(scenarios.len())
}

pub(crate) fn run_all(root: &Path) -> Result<usize, String> {
    let scenarios = validation::load_all(root)?;
    let artifact_root = root.join("target/scenario-artifacts");
    for scenario in &scenarios {
        println!("\n==> scenario {}", scenario.id);
        execution::run_one(root, &artifact_root, scenario)?;
        println!("scenario {}: PASS", scenario.id);
    }
    Ok(scenarios.len())
}
