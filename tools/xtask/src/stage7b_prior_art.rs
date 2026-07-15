use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

const MATRIX_PATH: &str = "evaluation/stage7b/prior-art.toml";
const CARD_DIRECTORY: &str = "evaluation/stage7b/prior-art-sources";
const JSON_OUTPUT: &str = "target/verification/stage7b/prior-art.json";
const LOG_OUTPUT: &str = "target/verification/stage7b/prior-art-oracle.log";
const RETRIEVED: &str = "2026-07-13";
const SHADOW_DRIVERS_RETRIEVED: &str = "2026-07-14";

const PRIOR_ART_FIELDS: &[&str] = &[
    "id",
    "primary_source",
    "source_locator",
    "mechanism",
    "authority_scope",
    "async_effect_tracking",
    "commit_or_linearization_gate",
    "crash_or_rebind_fencing",
    "resource_accounting",
    "device_quiescence",
    "overlap_with_cser",
    "difference_from_fixed_cser_boundary",
    "claim_impact",
];

const METADATA_ONLY_IDS: &[&str] = &["atomic-rpc"];
const FORBIDDEN_CLAIM_WORDS: &[&str] = &["novel", "novelty", "first", "proved"];

#[derive(Clone, Copy)]
struct ExpectedSource {
    id: &'static str,
    bibliographic_url: &'static str,
    access_url: &'static str,
    access_kind: &'static str,
    content_status: &'static str,
    source_content_sha256: &'static str,
    audit_notes_sha256: &'static str,
}

const EXPECTED_SOURCES: &[ExpectedSource] = &[
    ExpectedSource {
        id: "sel4.reply-capability-revoke",
        bibliographic_url: "https://sel4.systems/Info/Docs/seL4-manual-latest.pdf",
        access_url: "https://sel4.systems/Info/Docs/seL4-manual-latest.pdf",
        access_kind: "primary-full-text",
        content_status: "full-text-audited",
        source_content_sha256: "697b561c09fdbf88118efcf7bd609082e744c431d5b0dc76d377ca9ecfdd7c68",
        audit_notes_sha256: "02154ec0d33b15d6955713a62167386e2332edd890b4a5a1b009fc9a18971556",
    },
    ExpectedSource {
        id: "cornucopia.async-authority",
        bibliographic_url: "https://doi.org/10.1109/SP40000.2020.00098",
        access_url: "https://www.repository.cam.ac.uk/bitstreams/ca60eb0e-3d24-4460-997b-4fa6a3952307/download",
        access_kind: "primary-full-text",
        content_status: "full-text-audited",
        source_content_sha256: "aba64bb0171de17910f665a19b9dd99de08a4952d8eeea1bfa1b29f3844e0e77",
        audit_notes_sha256: "3488969b333cd1a7236bcfcde870b9b96cb9356ffbf565da3f4d5ee5bc625cf5",
    },
    ExpectedSource {
        id: "portico-lingering-authority",
        bibliographic_url: "https://arxiv.org/abs/2606.22504",
        access_url: "https://arxiv.org/pdf/2606.22504",
        access_kind: "primary-full-text",
        content_status: "full-text-audited",
        source_content_sha256: "45efdfa3d5a16a712f964ae79dbc46df8ef843904da137ad4baeebf83b125f84",
        audit_notes_sha256: "ad44b2e9a019fb9155a131d9a58e634ebfbea860ed9a8e9b008189ef3bb4cec3",
    },
    ExpectedSource {
        id: "vino.extension-fallback",
        bibliographic_url: "https://doi.org/10.1145/248155.238779",
        access_url: "https://www.usenix.org/legacy/publications/library/proceedings/osdi96/full_papers/seltzer/seltzer.ps",
        access_kind: "primary-full-text",
        content_status: "full-text-audited",
        source_content_sha256: "0c359f25cd2566280017540f2f16981cc8fb41bab9f68959377fd6758d153525",
        audit_notes_sha256: "98794084fabe7bff8e81010fdc48a69dbbf41aaaf7bb6188d13c882444d785a8",
    },
    ExpectedSource {
        id: "curios.restartable-services",
        bibliographic_url: "https://www.usenix.org/conference/osdi-08/curios-improving-reliability-through-operating-system-structure",
        access_url: "https://www.usenix.org/legacy/events/osdi08/tech/full_papers/david/david.pdf",
        access_kind: "primary-full-text",
        content_status: "full-text-audited",
        source_content_sha256: "cf7831aa5ae46d4e69fd61ae01a313aaf7eb524d43d7336848b4b8f407b18695",
        audit_notes_sha256: "7faadbe6778f21d039bc031214c46043f3f5bcd92cac1ec6cc254c96de0a7e72",
    },
    ExpectedSource {
        id: "shadow-drivers.device-recovery",
        bibliographic_url: "https://www.usenix.org/conference/osdi-04/recovering-device-drivers",
        access_url: "https://pages.cs.wisc.edu/~swift/papers/recovering-drivers.pdf",
        access_kind: "primary-full-text",
        content_status: "full-text-audited",
        source_content_sha256: "7489c8611bf48fe03cd84bc0c56757a7f95c2b8790cf95cb00106418e2c8a346",
        audit_notes_sha256: "003996a1dc2f41de1a2be15a86025c046188cd5c3b2697ddc7c50127532d17f5",
    },
    ExpectedSource {
        id: "txos.os-transactions",
        bibliographic_url: "https://doi.org/10.1145/1629575.1629591",
        access_url: "https://www.sigops.org/s/conferences/sosp/2009/papers/porter-sosp09.pdf",
        access_kind: "primary-full-text",
        content_status: "full-text-audited",
        source_content_sha256: "5b05f2783c543b27d37393d6cf48f3c63c16c69eb276b51e2b07bc3fa067b459",
        audit_notes_sha256: "3eebfc4954c5339348b5f5aa40d7040563fd3cc819effa7f37cfdd5046191486",
    },
    ExpectedSource {
        id: "speculator.causal-dependencies",
        bibliographic_url: "https://doi.org/10.1145/1095810.1095829",
        access_url: "https://web.eecs.umich.edu/~pmchen/papers/nightingale05.pdf",
        access_kind: "primary-full-text",
        content_status: "full-text-audited",
        source_content_sha256: "bd6e83fc0954d7e37a24f7245d11a7f1eaf42588f36307f5782c51bcd4eb6636",
        audit_notes_sha256: "81fd1241fb28abd9dbb9eee146cb918d3ce5a11c60b95ee26bd7a46115b79fc2",
    },
    ExpectedSource {
        id: "rethink-the-sync.causal-dependencies",
        bibliographic_url: "https://www.usenix.org/conference/osdi-06/rethink-sync",
        access_url: "https://www.usenix.org/legacy/events/osdi06/tech/nightingale/nightingale.pdf",
        access_kind: "primary-full-text",
        content_status: "full-text-audited",
        source_content_sha256: "dee41e8bdbb52c116cc4bd0fceb9c2d7349976f583601247e6a58d1abe43ec61",
        audit_notes_sha256: "a932951129d0758067c1421797275b725608a5658b84713cc761e1130a31839e",
    },
    ExpectedSource {
        id: "chubby.fencing",
        bibliographic_url: "https://www.usenix.org/conference/osdi-06/chubby-lock-service-loosely-coupled-distributed-systems",
        access_url: "https://www.usenix.org/legacy/events/osdi06/tech/full_papers/burrows/burrows.pdf",
        access_kind: "primary-full-text",
        content_status: "full-text-audited",
        source_content_sha256: "9d7cbad0760cc95d03595eadc188dc828237ba5645bceb7a15b9248ee02821bd",
        audit_notes_sha256: "936bea89098655df3b970f5207ebf6c6089f1d79d9fc56c16933c21b27f0b6d9",
    },
    ExpectedSource {
        id: "rifl.exactly-once-rpc",
        bibliographic_url: "https://doi.org/10.1145/2815400.2815416",
        access_url: "https://web.stanford.edu/~ouster/cgi-bin/papers/rifl.pdf",
        access_kind: "primary-full-text",
        content_status: "full-text-audited",
        source_content_sha256: "f609f9508beaf936027f31428a8f06dc86d8201faadc5b340ffead7706863969",
        audit_notes_sha256: "53e0c1dadba49f5da898e53530eaa059593b1c1e867808d8024309a86113af73",
    },
    ExpectedSource {
        id: "atomic-rpc",
        bibliographic_url: "https://doi.org/10.1109/TSE.1985.231860",
        access_url: "https://doi.org/10.1109/TSE.1985.231860",
        access_kind: "primary-metadata",
        content_status: "metadata-only-unavailable",
        source_content_sha256: "unavailable",
        audit_notes_sha256: "400330b5817d20f76c521ca5803828280aad6a4a8f02ec41f8bf5ac746394198",
    },
    ExpectedSource {
        id: "resource-containers",
        bibliographic_url: "https://www.usenix.org/conference/osdi-99/resource-containers-new-facility-resource-management-server-systems",
        access_url: "https://www.usenix.org/legacy/events/osdi99/full_papers/banga/banga.pdf",
        access_kind: "primary-full-text",
        content_status: "full-text-audited",
        source_content_sha256: "16d5319ada401f0ac582000b3fcdd9b34649f001cb11d84dc1d7974241aa3a77",
        audit_notes_sha256: "c3b3ff4a1258efa17d0da6e42794bcf611d1113b309ce4179e58353ad6325e66",
    },
    ExpectedSource {
        id: "fuchsia.rfc-0261",
        bibliographic_url: "https://fuchsia.dev/fuchsia-src/contribute/governance/rfcs/0261_fast_and_efficient_user_space_kernel_emulation",
        access_url: "https://fuchsia.dev/fuchsia-src/contribute/governance/rfcs/0261_fast_and_efficient_user_space_kernel_emulation",
        access_kind: "primary-web-document",
        content_status: "full-text-audited",
        source_content_sha256: "9436fa22361e5152590f0c637f36463cec6de27eb53daea3afce5b4e9907cbf9",
        audit_notes_sha256: "95824733b275c15f3bb2e6faf2ccd84398bd4bbd4aba20d8d42d0340a389177a",
    },
    ExpectedSource {
        id: "linux.io-uring-cancel",
        bibliographic_url: "https://github.com/axboe/liburing/blob/e50e32a6b9030faba2e30fa0ba999571a0cffe28/man/io_uring_prep_cancel.3",
        access_url: "https://raw.githubusercontent.com/axboe/liburing/e50e32a6b9030faba2e30fa0ba999571a0cffe28/man/io_uring_prep_cancel.3",
        access_kind: "primary-api-manual",
        content_status: "full-text-audited",
        source_content_sha256: "2d68eabbc809daa08d8ccd1394ca1de72079b926abb1d04c921ef1fae0483b7a",
        audit_notes_sha256: "b6a6d1b6bf02b1190d6bef8137e1d33e8c26a6b35e4c0d5e54b52c897e1f5514",
    },
    ExpectedSource {
        id: "virtio-1.3-reset",
        bibliographic_url: "https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.pdf",
        access_url: "https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.pdf",
        access_kind: "primary-specification",
        content_status: "full-text-audited",
        source_content_sha256: "17d95b4d1518054e7a49e4e2025e1433a4e8c92bb2181a889dcdaa74b9616675",
        audit_notes_sha256: "00404d2bf23a3bc94cd1bf7495e6082a849009ebfcf77cdfb39e853b3ae37be1",
    },
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    schema: String,
    contract: String,
    source_policy: String,
    source_card_directory: String,
    expected_count: usize,
    default_contribution_decision: String,
    decision_note: String,
    row: Vec<Row>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Row {
    id: String,
    primary_source: String,
    source_locator: String,
    mechanism: String,
    authority_scope: String,
    async_effect_tracking: String,
    commit_or_linearization_gate: String,
    crash_or_rebind_fencing: String,
    resource_accounting: String,
    device_quiescence: String,
    overlap_with_cser: String,
    difference_from_fixed_cser_boundary: String,
    claim_impact: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceCard {
    schema: String,
    id: String,
    title: String,
    authors: Vec<String>,
    year: u16,
    bibliographic_url: String,
    access_url: String,
    access_kind: String,
    retrieved: String,
    content_status: String,
    source_content_sha256: String,
    source_content_retained: bool,
    source_content_hash_scope: String,
    primary_source: String,
    source_locator: String,
    mechanism: String,
    authority_scope: String,
    async_effect_tracking: String,
    commit_or_linearization_gate: String,
    crash_or_rebind_fencing: String,
    resource_accounting: String,
    device_quiescence: String,
    overlap_with_cser: String,
    difference_from_fixed_cser_boundary: String,
    claim_impact: String,
    digest_algorithm: String,
    digest_scope: String,
    audit_notes: Vec<String>,
    audit_notes_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Summary {
    pub rows: usize,
    pub source_cards: usize,
    pub full_text: usize,
    pub metadata_only: usize,
    pub default_verdict: String,
    pub support_bounded_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    status: String,
    matrix: String,
    source_policy: String,
    summary: Summary,
    metadata_only_exclusions: Vec<String>,
    sources: Vec<ReceiptSource>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptSource {
    id: String,
    access_kind: String,
    content_status: String,
    bibliographic_url: String,
    source_content_sha256: String,
    audit_notes_sha256: String,
}

#[derive(Debug)]
struct Validated {
    summary: Summary,
    cards: Vec<SourceCard>,
}

pub fn run(root: &Path) -> Result<Summary, String> {
    clear_output(root, JSON_OUTPUT)?;
    clear_output(root, LOG_OUTPUT)?;
    let validated = validate(root)?;
    write_receipts(root, &validated)?;
    Ok(validated.summary)
}

pub fn check(root: &Path) -> Result<Summary, String> {
    validate(root).map(|validated| validated.summary)
}

pub(crate) fn accepted_summary() -> Summary {
    Summary {
        rows: EXPECTED_SOURCES.len(),
        source_cards: EXPECTED_SOURCES.len(),
        full_text: 15,
        metadata_only: 1,
        default_verdict: "narrow".into(),
        support_bounded_allowed: false,
    }
}

pub(crate) fn receipt_summary(root: &Path) -> Result<Summary, String> {
    let path = root.join(JSON_OUTPUT);
    require_regular_file(&path, JSON_OUTPUT)?;
    let source = fs::read(&path).map_err(|error| format!("read {JSON_OUTPUT}: {error}"))?;
    let receipt: Receipt =
        serde_json::from_slice(&source).map_err(|error| format!("parse {JSON_OUTPUT}: {error}"))?;
    let expected = accepted_receipt();
    if receipt != expected {
        return Err("prior-art receipt differs from the validated truth source contract".into());
    }
    Ok(receipt.summary)
}

#[cfg(test)]
pub(crate) fn accepted_receipt_json() -> Result<Vec<u8>, String> {
    let mut json = serde_json::to_vec_pretty(&accepted_receipt())
        .map_err(|error| format!("serialize accepted prior-art receipt: {error}"))?;
    json.push(b'\n');
    Ok(json)
}

fn validate(root: &Path) -> Result<Validated, String> {
    let matrix_path = root.join(MATRIX_PATH);
    require_regular_file(&matrix_path, MATRIX_PATH)?;
    let matrix_source =
        fs::read_to_string(&matrix_path).map_err(|error| format!("read {MATRIX_PATH}: {error}"))?;
    let matrix: Matrix =
        toml::from_str(&matrix_source).map_err(|error| format!("parse {MATRIX_PATH}: {error}"))?;
    validate_matrix(&matrix)?;

    let card_directory = root.join(CARD_DIRECTORY);
    require_regular_directory(&card_directory, CARD_DIRECTORY)?;
    validate_card_directory(&card_directory)?;

    let mut cards = Vec::with_capacity(EXPECTED_SOURCES.len());
    for (index, (row, expected)) in matrix.row.iter().zip(EXPECTED_SOURCES).enumerate() {
        let relative = format!("{CARD_DIRECTORY}/{}.toml", expected.id);
        let path = root.join(&relative);
        require_regular_file(&path, &relative)?;
        let source =
            fs::read_to_string(&path).map_err(|error| format!("read {relative}: {error}"))?;
        let card: SourceCard =
            toml::from_str(&source).map_err(|error| format!("parse {relative}: {error}"))?;
        validate_card(index, row, &card, expected)?;
        cards.push(card);
    }

    let full_text = cards
        .iter()
        .filter(|card| card.content_status == "full-text-audited")
        .count();
    let metadata_only = cards
        .iter()
        .filter(|card| card.content_status == "metadata-only-unavailable")
        .count();
    let accepted = accepted_summary();
    if full_text != accepted.full_text || metadata_only != accepted.metadata_only {
        return Err(format!(
            "prior-art source boundary mismatch: expected {} full-text and {} metadata-only, got {full_text} and {metadata_only}",
            accepted.full_text, accepted.metadata_only
        ));
    }

    let summary = Summary {
        rows: matrix.row.len(),
        source_cards: cards.len(),
        full_text,
        metadata_only,
        default_verdict: "narrow".into(),
        support_bounded_allowed: false,
    };
    if summary != accepted {
        return Err(format!(
            "prior-art summary differs from the accepted contract: expected {accepted:?}, got {summary:?}"
        ));
    }
    Ok(Validated { summary, cards })
}

fn validate_matrix(matrix: &Matrix) -> Result<(), String> {
    expect("schema", &matrix.schema, "nexus.stage7b.prior-art.v1")?;
    expect(
        "contract",
        &matrix.contract,
        "evaluation/stage7b/contract.toml",
    )?;
    expect(
        "source_policy",
        &matrix.source_policy,
        "primary-source-required",
    )?;
    expect(
        "source_card_directory",
        &matrix.source_card_directory,
        CARD_DIRECTORY,
    )?;
    if matrix.expected_count != EXPECTED_SOURCES.len() {
        return Err(format!(
            "expected_count mismatch: expected {}, got {}",
            EXPECTED_SOURCES.len(),
            matrix.expected_count
        ));
    }
    expect(
        "default_contribution_decision",
        &matrix.default_contribution_decision,
        "narrow",
    )?;
    if matrix.decision_note.trim().is_empty() {
        return Err("decision_note must not be empty".into());
    }
    if !matrix.decision_note.contains("Shadow Drivers")
        || !matrix.decision_note.contains("Atomic RPC")
        || !matrix
            .decision_note
            .contains("cannot support a stronger decision")
    {
        return Err(
            "decision_note must record the Shadow Drivers resolution and exclude unresolved Atomic RPC from a stronger decision"
                .into(),
        );
    }
    reject_forbidden_claim("decision_note", &matrix.decision_note)?;

    if matrix.row.len() != EXPECTED_SOURCES.len() {
        return Err(format!(
            "prior-art row count mismatch: expected {}, got {}",
            EXPECTED_SOURCES.len(),
            matrix.row.len()
        ));
    }
    let mut seen = BTreeSet::new();
    for (index, (row, expected)) in matrix.row.iter().zip(EXPECTED_SOURCES).enumerate() {
        if row.id != expected.id {
            return Err(format!(
                "prior-art row[{index}] order/id mismatch: expected {:?}, got {:?}",
                expected.id, row.id
            ));
        }
        if !seen.insert(row.id.as_str()) {
            return Err(format!("duplicate prior-art row id {:?}", row.id));
        }
        for (field, value) in PRIOR_ART_FIELDS.iter().zip(row_values(row)) {
            if value.trim().is_empty() {
                return Err(format!("prior-art row {} field {field} is empty", row.id));
            }
            reject_forbidden_claim(&format!("prior-art row {} field {field}", row.id), value)?;
        }
        if !is_primary_reference(&row.primary_source, expected) {
            return Err(format!(
                "prior-art row {} is secondary-only or lost its audited primary-source URL",
                row.id
            ));
        }
    }
    Ok(())
}

fn validate_card_directory(directory: &Path) -> Result<(), String> {
    let expected_names: BTreeSet<String> = EXPECTED_SOURCES
        .iter()
        .map(|source| format!("{}.toml", source.id))
        .collect();
    let mut actual_names = BTreeSet::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("read directory {CARD_DIRECTORY}: {error}"))?
    {
        let entry = entry.map_err(|error| format!("read entry in {CARD_DIRECTORY}: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("{CARD_DIRECTORY} contains a non-UTF-8 source-card file name"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("metadata {CARD_DIRECTORY}/{name}: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(format!(
                "source card {CARD_DIRECTORY}/{name} must be a regular non-symlink file"
            ));
        }
        actual_names.insert(name);
    }
    if actual_names != expected_names {
        let missing: Vec<_> = expected_names.difference(&actual_names).cloned().collect();
        let extra: Vec<_> = actual_names.difference(&expected_names).cloned().collect();
        return Err(format!(
            "source-card set mismatch: missing={missing:?} extra={extra:?}"
        ));
    }
    Ok(())
}

fn validate_card(
    index: usize,
    row: &Row,
    card: &SourceCard,
    expected: &ExpectedSource,
) -> Result<(), String> {
    expect(
        &format!("source card {} schema", expected.id),
        &card.schema,
        "nexus.stage7b.prior-art-source.v1",
    )?;
    expect(&format!("source card[{index}] id"), &card.id, expected.id)?;
    if card.title.trim().is_empty() || card.authors.is_empty() || card.year == 0 {
        return Err(format!(
            "source card {} requires non-empty title/authors and nonzero year",
            card.id
        ));
    }
    if card.authors.iter().any(|author| author.trim().is_empty()) {
        return Err(format!("source card {} has an empty author", card.id));
    }
    expect(
        &format!("source card {} bibliographic_url", card.id),
        &card.bibliographic_url,
        expected.bibliographic_url,
    )?;
    expect(
        &format!("source card {} access_url", card.id),
        &card.access_url,
        expected.access_url,
    )?;
    expect(
        &format!("source card {} access_kind", card.id),
        &card.access_kind,
        expected.access_kind,
    )?;
    let expected_retrieved = if card.id == "shadow-drivers.device-recovery" {
        SHADOW_DRIVERS_RETRIEVED
    } else {
        RETRIEVED
    };
    expect(
        &format!("source card {} retrieved", card.id),
        &card.retrieved,
        expected_retrieved,
    )?;
    expect(
        &format!("source card {} content_status", card.id),
        &card.content_status,
        expected.content_status,
    )?;
    expect(
        &format!("source card {} source_content_sha256", card.id),
        &card.source_content_sha256,
        expected.source_content_sha256,
    )?;
    if card.source_content_retained {
        return Err(format!(
            "source card {} must keep source_content_retained=false because source bytes are not checked in",
            card.id
        ));
    }
    if card.source_content_hash_scope.trim().is_empty() {
        return Err(format!(
            "source card {} source_content_hash_scope is empty",
            card.id
        ));
    }
    if expected.content_status == "full-text-audited" {
        require_sha256(
            &card.source_content_sha256,
            &format!("source card {} source_content_sha256", card.id),
        )?;
        if card.access_kind == "primary-metadata"
            || card.source_content_hash_scope.contains("unavailable")
        {
            return Err(format!(
                "source card {} full-text boundary contradicts its access/hash metadata",
                card.id
            ));
        }
    } else {
        if !METADATA_ONLY_IDS.contains(&card.id.as_str())
            || card.access_kind != "primary-metadata"
            || card.source_content_sha256 != "unavailable"
            || !card.source_content_hash_scope.contains("unavailable")
        {
            return Err(format!(
                "source card {} violates the metadata-only unavailable boundary",
                card.id
            ));
        }
        if card.difference_from_fixed_cser_boundary
            != "Unresolved pending primary full-text review."
            || !card
                .claim_impact
                .contains("prevents the matrix from supporting a stronger-than-narrow")
        {
            return Err(format!(
                "source card {} must explicitly exclude unresolved metadata from a stronger verdict",
                card.id
            ));
        }
    }

    for ((field, row_value), card_value) in PRIOR_ART_FIELDS
        .iter()
        .zip(row_values(row))
        .zip(card_values(card))
    {
        if row_value != card_value {
            return Err(format!(
                "source card {} field {field} does not match its matrix row",
                card.id
            ));
        }
    }
    if !is_primary_reference(&card.primary_source, expected) {
        return Err(format!(
            "source card {} is secondary-only or lost its audited primary-source URL",
            card.id
        ));
    }

    expect(
        &format!("source card {} digest_algorithm", card.id),
        &card.digest_algorithm,
        "sha256",
    )?;
    expect(
        &format!("source card {} digest_scope", card.id),
        &card.digest_scope,
        "UTF-8 bytes of audit_notes joined by LF in array order, with no trailing LF",
    )?;
    if card.audit_notes.is_empty() || card.audit_notes.iter().any(|note| note.trim().is_empty()) {
        return Err(format!(
            "source card {} requires non-empty bounded audit_notes",
            card.id
        ));
    }
    let audit_digest = sha256(card.audit_notes.join("\n").as_bytes());
    if audit_digest != card.audit_notes_sha256 {
        return Err(format!(
            "source card {} audit_notes digest mismatch: recomputed {}, recorded {}",
            card.id, audit_digest, card.audit_notes_sha256
        ));
    }
    expect(
        &format!("source card {} frozen audit_notes digest", card.id),
        &card.audit_notes_sha256,
        expected.audit_notes_sha256,
    )?;
    Ok(())
}

fn row_values(row: &Row) -> [&str; 13] {
    [
        &row.id,
        &row.primary_source,
        &row.source_locator,
        &row.mechanism,
        &row.authority_scope,
        &row.async_effect_tracking,
        &row.commit_or_linearization_gate,
        &row.crash_or_rebind_fencing,
        &row.resource_accounting,
        &row.device_quiescence,
        &row.overlap_with_cser,
        &row.difference_from_fixed_cser_boundary,
        &row.claim_impact,
    ]
}

fn card_values(card: &SourceCard) -> [&str; 13] {
    [
        &card.id,
        &card.primary_source,
        &card.source_locator,
        &card.mechanism,
        &card.authority_scope,
        &card.async_effect_tracking,
        &card.commit_or_linearization_gate,
        &card.crash_or_rebind_fencing,
        &card.resource_accounting,
        &card.device_quiescence,
        &card.overlap_with_cser,
        &card.difference_from_fixed_cser_boundary,
        &card.claim_impact,
    ]
}

fn is_primary_reference(value: &str, expected: &ExpectedSource) -> bool {
    let lowered = value.to_ascii_lowercase();
    ![
        "wikipedia",
        "openalex",
        "crossref",
        "semantic scholar",
        "secondary summary",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
        && (value.contains(expected.bibliographic_url) || value.contains(expected.access_url))
}

fn reject_forbidden_claim(label: &str, value: &str) -> Result<(), String> {
    for token in value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
    {
        if FORBIDDEN_CLAIM_WORDS.contains(&token.to_ascii_lowercase().as_str()) {
            return Err(format!(
                "{label} contains forbidden contribution/novelty word {token:?}"
            ));
        }
    }
    Ok(())
}

fn expect(label: &str, actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} mismatch: expected {expected:?}, got {actual:?}"
        ))
    }
}

fn require_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} must be a lowercase SHA-256 digest"))
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn require_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("metadata {label}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    Ok(())
}

fn require_regular_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("metadata {label}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(format!("{label} must be a regular non-symlink directory"));
    }
    Ok(())
}

fn write_receipts(root: &Path, validated: &Validated) -> Result<(), String> {
    let receipt = receipt_from_validated(validated);
    if receipt != accepted_receipt() {
        return Err("generated prior-art receipt differs from the accepted contract".into());
    }
    let mut json = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| format!("serialize {JSON_OUTPUT}: {error}"))?;
    json.push(b'\n');

    let mut log = String::new();
    log.push_str(&format!(
        "STAGE7B PRIOR_ART PASS rows={} source_cards={} full_text={} metadata_only={} default_verdict={} support_bounded_allowed={}\n",
        validated.summary.rows,
        validated.summary.source_cards,
        validated.summary.full_text,
        validated.summary.metadata_only,
        validated.summary.default_verdict,
        validated.summary.support_bounded_allowed,
    ));
    log.push_str(
        "PRIOR_ART METADATA_ONLY id=atomic-rpc status=metadata-only-unavailable exclusion=stronger-than-narrow\n",
    );
    for card in &validated.cards {
        log.push_str(&format!(
            "PRIOR_ART SOURCE id={} access_kind={} content_status={} source_sha256={} audit_notes_sha256={}\n",
            card.id,
            card.access_kind,
            card.content_status,
            card.source_content_sha256,
            card.audit_notes_sha256
        ));
    }
    log.push_str(
        "PRIOR_ART ORACLE PASS exact_order=true exact_fields=13 cards_regular_nonsymlink=true card_row_match=true primary_source_only=true audit_digests=16 forbidden_novelty=false support_bounded_allowed=false\n",
    );

    write_atomic(&root.join(LOG_OUTPUT), log.as_bytes())?;
    write_atomic(&root.join(JSON_OUTPUT), &json)?;
    Ok(())
}

fn receipt_from_validated(validated: &Validated) -> Receipt {
    Receipt {
        schema: "nexus.stage7b.prior-art.receipt.v1".into(),
        status: "passed".into(),
        matrix: MATRIX_PATH.into(),
        source_policy: "primary-source-required".into(),
        summary: validated.summary.clone(),
        metadata_only_exclusions: METADATA_ONLY_IDS
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
        sources: validated.cards.iter().map(receipt_source).collect(),
    }
}

fn accepted_receipt() -> Receipt {
    Receipt {
        schema: "nexus.stage7b.prior-art.receipt.v1".into(),
        status: "passed".into(),
        matrix: MATRIX_PATH.into(),
        source_policy: "primary-source-required".into(),
        summary: accepted_summary(),
        metadata_only_exclusions: METADATA_ONLY_IDS
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
        sources: EXPECTED_SOURCES
            .iter()
            .map(|source| ReceiptSource {
                id: source.id.into(),
                access_kind: source.access_kind.into(),
                content_status: source.content_status.into(),
                bibliographic_url: source.bibliographic_url.into(),
                source_content_sha256: source.source_content_sha256.into(),
                audit_notes_sha256: source.audit_notes_sha256.into(),
            })
            .collect(),
    }
}

fn receipt_source(card: &SourceCard) -> ReceiptSource {
    ReceiptSource {
        id: card.id.clone(),
        access_kind: card.access_kind.clone(),
        content_status: card.content_status.clone(),
        bibliographic_url: card.bibliographic_url.clone(),
        source_content_sha256: card.source_content_sha256.clone(),
        audit_notes_sha256: card.audit_notes_sha256.clone(),
    }
}

fn clear_output(root: &Path, relative: &str) -> Result<(), String> {
    let path = root.join(relative);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(&path).map_err(|error| format!("remove stale {relative}: {error}"))
        }
        Ok(_) => Err(format!("stale output {relative} is not a file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("metadata stale output {relative}: {error}")),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .ok_or_else(|| format!("output {} has no parent", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create output directory {}: {error}", parent.display()))?;
    let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("output {} has a non-UTF-8 name", path.display()))?;
    let temporary = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), sequence));
    let write_result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("create temporary output {}: {error}", temporary.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("write temporary output {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync temporary output {}: {error}", temporary.display()))?;
        fs::rename(&temporary, path).map_err(|error| {
            format!(
                "publish output {} as {}: {error}",
                temporary.display(),
                path.display()
            )
        })?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "nexus-stage7b-prior-art-test-{}-{sequence}",
                std::process::id()
            ));
            let source_root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .expect("repository root");
            let card_directory = root.join(CARD_DIRECTORY);
            fs::create_dir_all(&card_directory).expect("create fixture card directory");
            fs::copy(source_root.join(MATRIX_PATH), root.join(MATRIX_PATH))
                .expect("copy matrix fixture");
            for expected in EXPECTED_SOURCES {
                let name = format!("{}.toml", expected.id);
                fs::copy(
                    source_root.join(CARD_DIRECTORY).join(&name),
                    card_directory.join(name),
                )
                .expect("copy source card fixture");
            }
            Self { root }
        }

        fn matrix(&self) -> Matrix {
            toml::from_str(
                &fs::read_to_string(self.root.join(MATRIX_PATH)).expect("read matrix fixture"),
            )
            .expect("parse matrix fixture")
        }

        fn write_matrix(&self, matrix: &Matrix) {
            fs::write(
                self.root.join(MATRIX_PATH),
                toml::to_string_pretty(matrix).expect("serialize matrix fixture"),
            )
            .expect("write matrix fixture");
        }

        fn card(&self, id: &str) -> SourceCard {
            toml::from_str(
                &fs::read_to_string(self.card_path(id)).expect("read source card fixture"),
            )
            .expect("parse source card fixture")
        }

        fn write_card(&self, card: &SourceCard) {
            fs::write(
                self.card_path(&card.id),
                toml::to_string_pretty(card).expect("serialize source card fixture"),
            )
            .expect("write source card fixture");
        }

        fn card_path(&self, id: &str) -> PathBuf {
            self.root.join(CARD_DIRECTORY).join(format!("{id}.toml"))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn checked_in_truth_source_writes_narrow_receipts() {
        let fixture = Fixture::new();
        let summary = run(&fixture.root).expect("validate checked-in truth source");
        assert_eq!(
            summary,
            Summary {
                rows: 16,
                source_cards: 16,
                full_text: 15,
                metadata_only: 1,
                default_verdict: "narrow".into(),
                support_bounded_allowed: false,
            }
        );
        let json: serde_json::Value = serde_json::from_slice(
            &fs::read(fixture.root.join(JSON_OUTPUT)).expect("read JSON receipt"),
        )
        .expect("parse JSON receipt");
        assert_eq!(json["status"], "passed");
        assert_eq!(json["summary"]["full_text"], 15);
        assert_eq!(json["summary"]["metadata_only"], 1);
        assert_eq!(json["summary"]["default_verdict"], "narrow");
        assert_eq!(json["summary"]["support_bounded_allowed"], false);
        assert_eq!(json["metadata_only_exclusions"][0], METADATA_ONLY_IDS[0]);
        let log = fs::read_to_string(fixture.root.join(LOG_OUTPUT)).expect("read oracle log");
        assert!(log.contains("full_text=15 metadata_only=1"));
        assert!(log.contains("default_verdict=narrow support_bounded_allowed=false"));
        assert_eq!(log.matches("PRIOR_ART METADATA_ONLY").count(), 1);
        assert_eq!(log.matches("PRIOR_ART SOURCE").count(), 16);
        assert_eq!(
            receipt_summary(&fixture.root).expect("revalidate generated receipt"),
            summary
        );
    }

    #[test]
    fn rejects_receipt_summary_drift_from_the_validated_truth_source() {
        let fixture = Fixture::new();
        run(&fixture.root).expect("write valid receipt");
        let path = fixture.root.join(JSON_OUTPUT);
        let mut receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read receipt")).expect("parse receipt");
        receipt["summary"]["full_text"] = serde_json::json!(14);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&receipt).expect("serialize drifted receipt"),
        )
        .expect("write drifted receipt");

        assert!(
            receipt_summary(&fixture.root)
                .unwrap_err()
                .contains("differs from the validated truth source")
        );
    }

    #[test]
    fn rejects_missing_row_and_missing_card() {
        let fixture = Fixture::new();
        let mut matrix = fixture.matrix();
        matrix.row.remove(0);
        fixture.write_matrix(&matrix);
        assert!(
            validate(&fixture.root)
                .unwrap_err()
                .contains("row count mismatch")
        );

        let fixture = Fixture::new();
        fs::remove_file(fixture.card_path(EXPECTED_SOURCES[0].id)).expect("remove source card");
        assert!(
            validate(&fixture.root)
                .unwrap_err()
                .contains("source-card set mismatch")
        );
    }

    #[test]
    fn rejects_duplicate_row() {
        let fixture = Fixture::new();
        let mut matrix = fixture.matrix();
        matrix.row[1] = matrix.row[0].clone();
        fixture.write_matrix(&matrix);
        assert!(validate(&fixture.root).is_err());
    }

    #[test]
    fn rejects_reordered_rows() {
        let fixture = Fixture::new();
        let mut matrix = fixture.matrix();
        matrix.row.swap(0, 1);
        fixture.write_matrix(&matrix);
        assert!(
            validate(&fixture.root)
                .unwrap_err()
                .contains("order/id mismatch")
        );
    }

    #[test]
    fn rejects_secondary_only_source() {
        let fixture = Fixture::new();
        let mut matrix = fixture.matrix();
        matrix.row[0].primary_source =
            "Secondary summary https://en.wikipedia.org/wiki/Capability-based_security".into();
        fixture.write_matrix(&matrix);
        let mut card = fixture.card(EXPECTED_SOURCES[0].id);
        card.primary_source = matrix.row[0].primary_source.clone();
        fixture.write_card(&card);
        assert!(
            validate(&fixture.root)
                .unwrap_err()
                .contains("secondary-only")
        );
    }

    #[test]
    fn rejects_mutated_audit_note_digest() {
        let fixture = Fixture::new();
        let mut card = fixture.card(EXPECTED_SOURCES[0].id);
        card.audit_notes[0].push_str(" Mutated.");
        fixture.write_card(&card);
        assert!(
            validate(&fixture.root)
                .unwrap_err()
                .contains("audit_notes digest mismatch")
        );
    }

    #[test]
    fn rejects_card_matrix_mismatch() {
        let fixture = Fixture::new();
        let mut card = fixture.card(EXPECTED_SOURCES[0].id);
        card.mechanism.push_str(" Mutated.");
        fixture.write_card(&card);
        assert!(
            validate(&fixture.root)
                .unwrap_err()
                .contains("does not match its matrix row")
        );
    }

    #[test]
    fn rejects_forbidden_novelty_claim_even_when_card_matches() {
        let fixture = Fixture::new();
        let mut matrix = fixture.matrix();
        matrix.row[0].claim_impact = "This is a novel mechanism.".into();
        fixture.write_matrix(&matrix);
        let mut card = fixture.card(EXPECTED_SOURCES[0].id);
        card.claim_impact = matrix.row[0].claim_impact.clone();
        fixture.write_card(&card);
        assert!(
            validate(&fixture.root)
                .unwrap_err()
                .contains("forbidden contribution/novelty word")
        );
    }

    #[test]
    fn rejects_support_bounded_and_metadata_boundary_mutations() {
        let fixture = Fixture::new();
        let mut matrix = fixture.matrix();
        matrix.default_contribution_decision = "support-bounded".into();
        fixture.write_matrix(&matrix);
        assert!(
            validate(&fixture.root)
                .unwrap_err()
                .contains("default_contribution_decision mismatch")
        );

        let fixture = Fixture::new();
        let mut card = fixture.card(METADATA_ONLY_IDS[0]);
        card.content_status = "full-text-audited".into();
        fixture.write_card(&card);
        assert!(
            validate(&fixture.root)
                .unwrap_err()
                .contains("content_status mismatch")
        );
    }

    #[test]
    fn rejects_symlink_source_card() {
        let fixture = Fixture::new();
        let id = EXPECTED_SOURCES[0].id;
        let card_path = fixture.card_path(id);
        let outside = fixture.root.join("outside-card.toml");
        fs::copy(&card_path, &outside).expect("copy source card outside directory");
        fs::remove_file(&card_path).expect("remove regular source card");
        symlink(&outside, &card_path).expect("symlink source card");
        assert!(
            validate(&fixture.root)
                .unwrap_err()
                .contains("regular non-symlink")
        );
    }
}
