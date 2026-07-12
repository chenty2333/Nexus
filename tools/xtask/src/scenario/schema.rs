use serde::Deserialize;

pub(super) const MIN_OUTPUT_BYTES: u64 = 1_024;
pub(super) const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const FAILURE_METADATA: &str = "failure.toml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScenarioFile {
    pub(super) schema_version: u32,
    pub(super) scenario: Vec<Scenario>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Scenario {
    pub(super) id: String,
    pub(super) command: Vec<String>,
    pub(super) timeout_ms: u64,
    pub(super) max_output_bytes: u64,
    #[serde(default = "successful_exit")]
    pub(super) expected_exit: i32,
    pub(super) serial: SerialOracle,
    #[serde(default)]
    pub(super) numeric: Vec<NumericOracle>,
    pub(super) artifacts: ArtifactPolicy,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SerialOracle {
    #[serde(default)]
    pub(super) expect: Vec<String>,
    #[serde(default)]
    pub(super) ordered: Vec<String>,
    #[serde(default)]
    pub(super) forbid: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NumericOracle {
    pub(super) key: String,
    pub(super) exact: Option<i64>,
    pub(super) min: Option<i64>,
    pub(super) max: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Retain {
    Always,
    OnFailure,
    Never,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactPolicy {
    pub(super) retain: Retain,
    pub(super) serial: String,
}

fn successful_exit() -> i32 {
    0
}
