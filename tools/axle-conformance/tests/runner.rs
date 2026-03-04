use std::fs;

use axle_conformance::runner::{RunConfig, run_conformance};

fn write_file(path: &std::path::Path, content: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir parent");
    fs::write(path, content).expect("write file");
}

#[test]
fn run_conformance_writes_summary_and_reports_pass() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ws = tmp.path();

    let scenarios_dir = ws.join("specs/conformance/scenarios");
    let contracts_file = ws.join("specs/conformance/contracts.toml");
    write_file(
        &scenarios_dir.join("ok.toml"),
        r#"
id = "sample.pass"
tags = ["module:sample"]
timeout_ms = 1000
command = ["sh", "-c", "echo pass"]
expect = ["pass"]
forbid = ["panic"]
contracts = ["must.sample.pass"]
"#,
    );
    write_file(
        &contracts_file,
        r#"
schema_version = 1
[[contracts]]
id = "must.sample.pass"
level = "must"
description = "sample contract"
"#,
    );

    let out_dir = ws.join("target/axle-conformance");
    let config = RunConfig {
        scenario_filters: vec![],
        tag_filters: vec![],
        keep_runs: 100,
        verbose: false,
        out_dir: out_dir.clone(),
        scenarios_dir,
        contracts_file,
        workspace_root: ws.to_path_buf(),
        jobs: 1,
        retries: 0,
    };

    let summary = run_conformance(&config).expect("run conformance");
    assert_eq!(summary.total, 1);
    assert_eq!(summary.pass, 1);
    assert_eq!(summary.fail, 0);

    let summary_path = std::path::Path::new(&summary.report_path);
    assert!(summary_path.exists());
}
