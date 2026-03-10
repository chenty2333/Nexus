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
[contracts.concurrency]
mode = "not_applicable"
reason = "sample runner fixture"
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
    assert_eq!(summary.groups.len(), 1);

    let summary_path = std::path::Path::new(&summary.report_path);
    assert!(summary_path.exists());
}

#[test]
fn run_conformance_reuses_shared_command_output() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ws = tmp.path();

    let scenarios_dir = ws.join("specs/conformance/scenarios");
    let contracts_file = ws.join("specs/conformance/contracts.toml");
    let count_file = ws.join("shared-count.txt");
    let command = format!(
        "count=$(cat \"{}\" 2>/dev/null || echo 0); count=$((count+1)); echo \"$count\" > \"{}\"; echo shared-pass",
        count_file.display(),
        count_file.display()
    );

    write_file(
        &scenarios_dir.join("first.toml"),
        &format!(
            r#"
id = "sample.first"
tags = ["module:sample"]
timeout_ms = 1000
command = ['sh', '-c', '{command}']
expect = ["shared-pass"]
forbid = ["panic"]
contracts = ["must.sample.first"]
"#
        ),
    );
    write_file(
        &scenarios_dir.join("second.toml"),
        &format!(
            r#"
id = "sample.second"
tags = ["module:sample"]
timeout_ms = 1000
command = ['sh', '-c', '{command}']
expect = ["shared-pass"]
forbid = ["panic"]
contracts = ["must.sample.second"]
"#
        ),
    );
    write_file(
        &contracts_file,
        r#"
schema_version = 1
[[contracts]]
id = "must.sample.first"
level = "must"
description = "sample contract first"
[contracts.concurrency]
mode = "not_applicable"
reason = "sample runner fixture"

[[contracts]]
id = "must.sample.second"
level = "must"
description = "sample contract second"
[contracts.concurrency]
mode = "not_applicable"
reason = "sample runner fixture"
"#,
    );

    let out_dir = ws.join("target/axle-conformance");
    let config = RunConfig {
        scenario_filters: vec![],
        tag_filters: vec![],
        keep_runs: 100,
        verbose: false,
        out_dir,
        scenarios_dir,
        contracts_file,
        workspace_root: ws.to_path_buf(),
        jobs: 1,
        retries: 0,
    };

    let summary = run_conformance(&config).expect("run conformance");
    assert_eq!(summary.total, 2);
    assert_eq!(summary.pass, 2);
    assert_eq!(summary.fail, 0);
    assert_eq!(summary.groups.len(), 1);

    let count = fs::read_to_string(&count_file).expect("read counter");
    assert_eq!(count.trim(), "1");
}
