use quote::ToTokens as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};
use std::process::Command;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ImplItem, Item, Type};

const OVERLAY_PATH: &str = "evaluation/production-identity/causal-evidence-overlay.toml";
const OVERLAY_SCHEMA: &str = "nexus.research.production-identity.causal-evidence-overlay.v2";
const RFC_PATH: &str = "docs/rfcs/0003-causal-coverage-closure.md";
const BASE_COVERAGE_PATH: &str = "evaluation/production-identity/causal-coverage.toml";
const BASE_COVERAGE_SHA256: &str =
    "5f2d71fadf0275217f0e28ede923551fb84b5a7530c832a81930e9ce24c54bbe";
const BASE_MATRIX_PATH: &str = "evaluation/production-identity/causal-fault-matrix.toml";
const BASE_MATRIX_SHA256: &str = "9813ee8d26a2d72b383d8c4a7fbf7b193d8b0b1aa84e0fe49d4645fdd9ad818e";
const BASE_MATRIX_SEMANTIC_SHA256: &str =
    "fdd636526fde6c77d17d3a1acd9e4cb88a030230c4aeaa9f2cdf9245d5d05075";
const BASE_MATRIX_SCHEMA: &str = "nexus.research.production-identity.causal-fault-matrix.v1";
const BASE_CELL_COUNT: usize = 66;
const BASE_STATE: &str = "planned";
const STATUS_EMPTY: &str = "incomplete-no-promotions";
const STATUS_PROGRESS: &str = "incomplete-promotions-recorded";
const ROOT_OWNED_OBLIGATION: &str = "root-owned-obligation";
const STATIC_REACHABILITY_GATE: &str =
    "exact-non-test-symbol-chain-normal-callsite-to-production-to-injection";
const STATIC_REACHABILITY_LIMITATION: &str = "syntactic-rust-ast-edge-check-only-not-name-resolution-cfg-proof-link-proof-or-runtime-execution";
const PROMOTION_HISTORY_LIMITATION: &str =
    "append-only-prefix-is-repository-review-policy-validator-cannot-detect-rewritten-git-history";
const CLASSIFICATIONS: &[&str] = &[
    "tracked-effect",
    "root-owned-publication",
    ROOT_OWNED_OBLIGATION,
    "kernel-tcb-infrastructure",
    "uncovered-gap",
];
const EVIDENCE_STATES: &[&str] = &["planned", "source-mapped", "observed"];

#[derive(Debug)]
pub(crate) struct Summary {
    pub(crate) cells: usize,
    pub(crate) promotions: usize,
    pub(crate) planned: usize,
    pub(crate) source_mapped: usize,
    pub(crate) observed: usize,
    pub(crate) complete: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Overlay {
    schema: String,
    overlay_revision: usize,
    as_of: String,
    rfc: String,
    base_coverage: String,
    base_coverage_sha256: String,
    base_matrix: String,
    base_matrix_sha256: String,
    base_matrix_semantic_sha256: String,
    base_cell_count: usize,
    base_state: String,
    status: String,
    complete: bool,
    allowed_classifications: Vec<String>,
    allowed_evidence_states: Vec<String>,
    promotion_count: usize,
    planned_count: usize,
    source_mapped_count: usize,
    observed_count: usize,
    static_reachability_gate: String,
    static_reachability_limitation: String,
    promotion_history_limitation: String,
    #[serde(default)]
    promotion: Vec<Promotion>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Promotion {
    sequence: usize,
    cell_id: String,
    tranche: String,
    boundary: String,
    from: String,
    to: String,
    classification: String,
    recorded_on: String,
    #[serde(default)]
    source_mapping: Option<SourceMapping>,
    #[serde(default)]
    observation: Option<Observation>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceMapping {
    revision: String,
    production: SourceSymbol,
    normal_callsite: SourceSymbol,
    injection: SourceSymbol,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct SourceSymbol {
    path: String,
    symbol: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    revision: String,
    qemu_profile: String,
    qemu_artifact_path: String,
    qemu_artifact_sha256: String,
    receipt_path: String,
    receipt_sha256: String,
    receipt_schema: String,
}

#[derive(Debug, Deserialize)]
struct BaseMatrix {
    schema: String,
    expected_count: usize,
    cell: Vec<BaseCell>,
}

#[derive(Clone, Debug, Deserialize)]
struct BaseCell {
    id: String,
    tranche: String,
    boundary: String,
}

#[derive(Clone, Debug)]
struct CellProgress {
    state: &'static str,
    source_mapping: Option<SourceMapping>,
}

#[derive(Clone, Debug)]
struct SymbolFacts {
    test_only: bool,
    references: BTreeSet<String>,
}

pub(crate) fn validate(root: &Path) -> Result<Summary, String> {
    let matrix_summary = super::causal_fault_matrix::validate(root)
        .map_err(|error| format!("base v1 matrix: {error}"))?;
    if matrix_summary.cells != BASE_CELL_COUNT
        || matrix_summary.planned != BASE_CELL_COUNT
        || matrix_summary.source_mapped != 0
        || matrix_summary.observed != 0
        || matrix_summary.canonical_sha256 != BASE_MATRIX_SEMANTIC_SHA256
    {
        return Err("base v1 matrix semantic population drifted".into());
    }

    let coverage = read_regular_bytes(root, BASE_COVERAGE_PATH)?;
    require_digest(BASE_COVERAGE_PATH, &coverage, BASE_COVERAGE_SHA256)?;
    let matrix = read_regular_bytes(root, BASE_MATRIX_PATH)?;
    require_digest(BASE_MATRIX_PATH, &matrix, BASE_MATRIX_SHA256)?;
    let base: BaseMatrix = toml::from_str(
        std::str::from_utf8(&matrix)
            .map_err(|error| format!("{BASE_MATRIX_PATH} is not UTF-8: {error}"))?,
    )
    .map_err(|error| format!("parse {BASE_MATRIX_PATH} for overlay: {error}"))?;

    let bytes = read_regular_bytes(root, OVERLAY_PATH)?;
    let overlay: Overlay = toml::from_str(
        std::str::from_utf8(&bytes)
            .map_err(|error| format!("{OVERLAY_PATH} is not UTF-8: {error}"))?,
    )
    .map_err(|error| format!("parse {OVERLAY_PATH}: {error}"))?;
    validate_document(root, &overlay, &base)
}

fn validate_document(root: &Path, overlay: &Overlay, base: &BaseMatrix) -> Result<Summary, String> {
    require_eq("schema", &overlay.schema, OVERLAY_SCHEMA)?;
    if overlay.overlay_revision == 0 {
        return Err("overlay_revision must be positive".into());
    }
    require_date("as_of", &overlay.as_of)?;
    require_eq("rfc", &overlay.rfc, RFC_PATH)?;
    require_eq("base_coverage", &overlay.base_coverage, BASE_COVERAGE_PATH)?;
    require_eq(
        "base_coverage_sha256",
        &overlay.base_coverage_sha256,
        BASE_COVERAGE_SHA256,
    )?;
    require_eq("base_matrix", &overlay.base_matrix, BASE_MATRIX_PATH)?;
    require_eq(
        "base_matrix_sha256",
        &overlay.base_matrix_sha256,
        BASE_MATRIX_SHA256,
    )?;
    require_eq(
        "base_matrix_semantic_sha256",
        &overlay.base_matrix_semantic_sha256,
        BASE_MATRIX_SEMANTIC_SHA256,
    )?;
    require_eq("base matrix schema", &base.schema, BASE_MATRIX_SCHEMA)?;
    if overlay.base_cell_count != BASE_CELL_COUNT
        || base.expected_count != BASE_CELL_COUNT
        || base.cell.len() != BASE_CELL_COUNT
    {
        return Err(format!(
            "overlay base must remain the exact {BASE_CELL_COUNT}-cell v1 population"
        ));
    }
    require_eq("base_state", &overlay.base_state, BASE_STATE)?;
    if overlay.complete {
        return Err("causal evidence overlay complete must remain false".into());
    }
    require_exact_list(
        "allowed_classifications",
        &overlay.allowed_classifications,
        CLASSIFICATIONS,
    )?;
    require_exact_list(
        "allowed_evidence_states",
        &overlay.allowed_evidence_states,
        EVIDENCE_STATES,
    )?;
    require_eq(
        "static_reachability_gate",
        &overlay.static_reachability_gate,
        STATIC_REACHABILITY_GATE,
    )?;
    require_eq(
        "static_reachability_limitation",
        &overlay.static_reachability_limitation,
        STATIC_REACHABILITY_LIMITATION,
    )?;
    require_eq(
        "promotion_history_limitation",
        &overlay.promotion_history_limitation,
        PROMOTION_HISTORY_LIMITATION,
    )?;

    let base_cells = validate_base_population(base)?;
    let mut progress = base_cells
        .keys()
        .map(|id| {
            (
                id.clone(),
                CellProgress {
                    state: BASE_STATE,
                    source_mapping: None,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    for (index, promotion) in overlay.promotion.iter().enumerate() {
        let expected_sequence = index + 1;
        if promotion.sequence != expected_sequence {
            return Err(format!(
                "promotion[{index}] sequence must be {expected_sequence}, found {}",
                promotion.sequence
            ));
        }
        let base_cell = base_cells
            .get(&promotion.cell_id)
            .ok_or_else(|| format!("unknown or renamed causal cell {}", promotion.cell_id))?;
        if promotion.tranche != base_cell.tranche || promotion.boundary != base_cell.boundary {
            return Err(format!(
                "promotion {} changes frozen tranche/boundary identity",
                promotion.cell_id
            ));
        }
        require_eq(
            &format!("promotion {} classification", promotion.cell_id),
            &promotion.classification,
            ROOT_OWNED_OBLIGATION,
        )?;
        require_date(
            &format!("promotion {} recorded_on", promotion.cell_id),
            &promotion.recorded_on,
        )?;

        let cell = progress.get_mut(&promotion.cell_id).unwrap();
        if promotion.from != cell.state {
            return Err(format!(
                "promotion {} is non-monotonic or duplicate: current state is {}, transition starts at {}",
                promotion.cell_id, cell.state, promotion.from
            ));
        }
        match (promotion.from.as_str(), promotion.to.as_str()) {
            ("planned", "source-mapped") => {
                let mapping = promotion.source_mapping.as_ref().ok_or_else(|| {
                    format!(
                        "promotion {} planned -> source-mapped requires exact source_mapping",
                        promotion.cell_id
                    )
                })?;
                if promotion.observation.is_some() {
                    return Err(format!(
                        "promotion {} cannot attach runtime observation before source mapping is accepted",
                        promotion.cell_id
                    ));
                }
                validate_source_mapping(root, &promotion.cell_id, mapping)?;
                cell.state = "source-mapped";
                cell.source_mapping = Some(mapping.clone());
            }
            ("source-mapped", "observed") => {
                if promotion.source_mapping.is_some() {
                    return Err(format!(
                        "promotion {} must not rewrite its accepted source mapping",
                        promotion.cell_id
                    ));
                }
                let observation = promotion.observation.as_ref().ok_or_else(|| {
                    format!(
                        "promotion {} source-mapped -> observed requires exact observation",
                        promotion.cell_id
                    )
                })?;
                let mapping = cell.source_mapping.as_ref().ok_or_else(|| {
                    format!("promotion {} lost its source mapping", promotion.cell_id)
                })?;
                validate_observation(root, &promotion.cell_id, mapping, observation)?;
                cell.state = "observed";
            }
            _ => {
                return Err(format!(
                    "promotion {} may only advance planned -> source-mapped -> observed, found {} -> {}",
                    promotion.cell_id, promotion.from, promotion.to
                ));
            }
        }
    }

    let planned = progress
        .values()
        .filter(|cell| cell.state == "planned")
        .count();
    let source_mapped = progress
        .values()
        .filter(|cell| cell.state == "source-mapped")
        .count();
    let observed = progress
        .values()
        .filter(|cell| cell.state == "observed")
        .count();
    if overlay.promotion_count != overlay.promotion.len() {
        return Err(format!(
            "promotion_count={}, but transition log contains {} rows",
            overlay.promotion_count,
            overlay.promotion.len()
        ));
    }
    if (
        overlay.planned_count,
        overlay.source_mapped_count,
        overlay.observed_count,
    ) != (planned, source_mapped, observed)
    {
        return Err(format!(
            "overlay evidence counts drifted: declared planned={} source-mapped={} observed={}, replayed planned={planned} source-mapped={source_mapped} observed={observed}",
            overlay.planned_count, overlay.source_mapped_count, overlay.observed_count
        ));
    }
    let expected_status = if overlay.promotion.is_empty() {
        STATUS_EMPTY
    } else {
        STATUS_PROGRESS
    };
    require_eq("status", &overlay.status, expected_status)?;

    Ok(Summary {
        cells: progress.len(),
        promotions: overlay.promotion.len(),
        planned,
        source_mapped,
        observed,
        complete: overlay.complete,
    })
}

fn validate_base_population(base: &BaseMatrix) -> Result<BTreeMap<String, BaseCell>, String> {
    let mut cells = BTreeMap::new();
    for cell in &base.cell {
        require_token("base cell id", &cell.id)?;
        require_token(&format!("base cell {} tranche", cell.id), &cell.tranche)?;
        require_token(&format!("base cell {} boundary", cell.id), &cell.boundary)?;
        if cells.insert(cell.id.clone(), cell.clone()).is_some() {
            return Err(format!("duplicate base causal cell {}", cell.id));
        }
    }
    if cells.len() != BASE_CELL_COUNT {
        return Err(format!(
            "base causal cell identity population must remain {BASE_CELL_COUNT}"
        ));
    }
    Ok(cells)
}

fn validate_source_mapping(
    root: &Path,
    cell_id: &str,
    mapping: &SourceMapping,
) -> Result<(), String> {
    require_full_revision(
        &format!("source mapping {cell_id} revision"),
        &mapping.revision,
    )?;
    require_ancestor_revision(root, &mapping.revision)?;
    if mapping.production == mapping.normal_callsite
        || mapping.production == mapping.injection
        || mapping.normal_callsite == mapping.injection
    {
        return Err(format!(
            "source mapping {cell_id} must bind three distinct exact symbols"
        ));
    }

    let references = [
        ("production", &mapping.production),
        ("normal_callsite", &mapping.normal_callsite),
        ("injection", &mapping.injection),
    ];
    let mut current_files = BTreeMap::new();
    let mut revision_files = BTreeMap::new();
    for (role, reference) in references {
        validate_source_symbol_shape(cell_id, role, reference)?;
        if !current_files.contains_key(&reference.path) {
            let bytes = read_regular_bytes(root, &reference.path).map_err(|error| {
                format!(
                    "source mapping {cell_id} current {}: {error}",
                    reference.path
                )
            })?;
            current_files.insert(
                reference.path.clone(),
                parse_symbols(&reference.path, &bytes)?,
            );
        }
        if !revision_files.contains_key(&reference.path) {
            let bytes = read_git_regular_bytes(root, &mapping.revision, &reference.path)
                .map_err(|error| format!("source mapping {cell_id} revision: {error}"))?;
            revision_files.insert(
                reference.path.clone(),
                parse_symbols(&reference.path, &bytes)?,
            );
        }
    }

    for (role, reference) in references {
        validate_mapped_symbol(
            cell_id,
            role,
            reference,
            current_files.get(&reference.path).unwrap(),
        )?;
        validate_mapped_symbol(
            cell_id,
            role,
            reference,
            revision_files.get(&reference.path).unwrap(),
        )?;
    }
    validate_static_edge(
        cell_id,
        "normal workload callsite -> production",
        &mapping.normal_callsite,
        &mapping.production,
        &current_files,
    )?;
    validate_static_edge(
        cell_id,
        "production -> injection",
        &mapping.production,
        &mapping.injection,
        &current_files,
    )?;
    validate_static_edge(
        cell_id,
        "revision normal workload callsite -> production",
        &mapping.normal_callsite,
        &mapping.production,
        &revision_files,
    )?;
    validate_static_edge(
        cell_id,
        "revision production -> injection",
        &mapping.production,
        &mapping.injection,
        &revision_files,
    )
}

fn validate_source_symbol_shape(
    cell_id: &str,
    role: &str,
    reference: &SourceSymbol,
) -> Result<(), String> {
    validate_relative_path(&format!("source mapping {cell_id} {role}"), &reference.path)?;
    if !reference.path.ends_with(".rs") {
        return Err(format!(
            "source mapping {cell_id} {role} must name a Rust source file"
        ));
    }
    validate_symbol_name(
        &format!("source mapping {cell_id} {role} symbol"),
        &reference.symbol,
    )
}

fn validate_mapped_symbol(
    cell_id: &str,
    role: &str,
    reference: &SourceSymbol,
    symbols: &BTreeMap<String, SymbolFacts>,
) -> Result<(), String> {
    let facts = symbols.get(&reference.symbol).ok_or_else(|| {
        format!(
            "source mapping {cell_id} {role} symbol {} is missing from {}",
            reference.symbol, reference.path
        )
    })?;
    if facts.test_only || is_test_named(&reference.path, &reference.symbol) {
        return Err(format!(
            "source mapping {cell_id} {role} symbol {} is test-only, not a normal workload boundary",
            reference.symbol
        ));
    }
    Ok(())
}

fn validate_static_edge(
    cell_id: &str,
    edge: &str,
    caller: &SourceSymbol,
    callee: &SourceSymbol,
    files: &BTreeMap<String, BTreeMap<String, SymbolFacts>>,
) -> Result<(), String> {
    let facts = files
        .get(&caller.path)
        .and_then(|symbols| symbols.get(&caller.symbol))
        .ok_or_else(|| format!("source mapping {cell_id} lost caller {}", caller.symbol))?;
    let target = callee.symbol.rsplit("::").next().unwrap();
    if !facts.references.contains(target) {
        return Err(format!(
            "source mapping {cell_id} lacks static {edge} edge: {} does not reference {}",
            caller.symbol, callee.symbol
        ));
    }
    Ok(())
}

fn validate_observation(
    root: &Path,
    cell_id: &str,
    mapping: &SourceMapping,
    observation: &Observation,
) -> Result<(), String> {
    require_full_revision(
        &format!("observation {cell_id} revision"),
        &observation.revision,
    )?;
    if observation.revision != mapping.revision {
        return Err(format!(
            "observation {cell_id} revision drift: source mapping binds {}, observation names {}",
            mapping.revision, observation.revision
        ));
    }
    require_ancestor_revision(root, &observation.revision)?;
    require_token(
        &format!("observation {cell_id} qemu_profile"),
        &observation.qemu_profile,
    )?;
    if !observation.qemu_profile.starts_with("nexus-ostd-qemu-") {
        return Err(format!(
            "observation {cell_id} qemu_profile must start with nexus-ostd-qemu-"
        ));
    }
    if observation.qemu_artifact_path == observation.receipt_path {
        return Err(format!(
            "observation {cell_id} must bind distinct QEMU artifact and receipt files"
        ));
    }
    let artifact = read_regular_bytes(root, &observation.qemu_artifact_path)
        .map_err(|error| format!("observation {cell_id} QEMU artifact: {error}"))?;
    require_digest(
        &format!("observation {cell_id} QEMU artifact"),
        &artifact,
        &observation.qemu_artifact_sha256,
    )?;
    let receipt = read_regular_bytes(root, &observation.receipt_path)
        .map_err(|error| format!("observation {cell_id} receipt: {error}"))?;
    require_digest(
        &format!("observation {cell_id} receipt"),
        &receipt,
        &observation.receipt_sha256,
    )?;
    require_nonempty(
        &format!("observation {cell_id} receipt_schema"),
        &observation.receipt_schema,
    )?;
    if !observation.receipt_schema.starts_with("nexus.") {
        return Err(format!(
            "observation {cell_id} receipt_schema must be a versioned nexus schema"
        ));
    }
    let receipt_text = std::str::from_utf8(&receipt)
        .map_err(|error| format!("observation {cell_id} receipt is not UTF-8: {error}"))?;
    for (field, expected) in [
        ("cell id", cell_id),
        ("revision", observation.revision.as_str()),
        ("schema", observation.receipt_schema.as_str()),
    ] {
        if !receipt_text.contains(expected) {
            return Err(format!(
                "observation {cell_id} receipt does not bind exact {field} {expected}"
            ));
        }
    }
    Ok(())
}

fn parse_symbols(source_path: &str, bytes: &[u8]) -> Result<BTreeMap<String, SymbolFacts>, String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|error| format!("source {source_path} is not UTF-8: {error}"))?;
    let file = syn::parse_file(source)
        .map_err(|error| format!("parse Rust source {source_path}: {error}"))?;
    let mut symbols = BTreeMap::new();
    collect_items(&file.items, &[], false, &mut symbols)?;
    Ok(symbols)
}

fn collect_items(
    items: &[Item],
    module_prefix: &[String],
    inherited_test_only: bool,
    symbols: &mut BTreeMap<String, SymbolFacts>,
) -> Result<(), String> {
    for item in items {
        match item {
            Item::Fn(function) => {
                let name = qualified_name(module_prefix, None, &function.sig.ident.to_string());
                insert_symbol(
                    symbols,
                    name,
                    inherited_test_only || attributes_are_test_only(&function.attrs),
                    references_in_block(&function.block),
                )?;
            }
            Item::Impl(implementation) => {
                let test_only =
                    inherited_test_only || attributes_are_test_only(&implementation.attrs);
                let Some(owner) = simple_type_name(&implementation.self_ty) else {
                    continue;
                };
                for member in &implementation.items {
                    if let ImplItem::Fn(function) = member {
                        let name = qualified_name(
                            module_prefix,
                            Some(&owner),
                            &function.sig.ident.to_string(),
                        );
                        insert_symbol(
                            symbols,
                            name,
                            test_only || attributes_are_test_only(&function.attrs),
                            references_in_block(&function.block),
                        )?;
                    }
                }
            }
            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    let mut prefix = module_prefix.to_vec();
                    prefix.push(module.ident.to_string());
                    collect_items(
                        nested,
                        &prefix,
                        inherited_test_only || attributes_are_test_only(&module.attrs),
                        symbols,
                    )?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn insert_symbol(
    symbols: &mut BTreeMap<String, SymbolFacts>,
    name: String,
    test_only: bool,
    references: BTreeSet<String>,
) -> Result<(), String> {
    if symbols
        .insert(
            name.clone(),
            SymbolFacts {
                test_only,
                references,
            },
        )
        .is_some()
    {
        return Err(format!("ambiguous duplicate Rust symbol {name}"));
    }
    Ok(())
}

fn qualified_name(prefix: &[String], owner: Option<&str>, function: &str) -> String {
    prefix
        .iter()
        .map(String::as_str)
        .chain(owner)
        .chain([function])
        .collect::<Vec<_>>()
        .join("::")
}

fn simple_type_name(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn attributes_are_test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("test")
            || (attribute.path().is_ident("cfg")
                && attribute
                    .meta
                    .to_token_stream()
                    .to_string()
                    .contains("test"))
    })
}

fn is_test_named(path: &str, symbol: &str) -> bool {
    let path_components = Path::new(path)
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    let name = symbol.rsplit("::").next().unwrap_or(symbol);
    path_components.iter().any(|component| {
        *component == "tests"
            || *component == "tests.rs"
            || component.ends_with("_test.rs")
            || component.ends_with("_tests.rs")
    }) || name == "test"
        || name.starts_with("test_")
        || name.ends_with("_test")
        || name.contains("self_test")
}

fn references_in_block(block: &syn::Block) -> BTreeSet<String> {
    let mut collector = ReferenceCollector::default();
    collector.visit_block(block);
    collector.references
}

#[derive(Default)]
struct ReferenceCollector {
    references: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ReferenceCollector {
    fn visit_expr(&mut self, expression: &'ast Expr) {
        match expression {
            Expr::Path(path) => {
                if let Some(segment) = path.path.segments.last() {
                    self.references.insert(segment.ident.to_string());
                }
            }
            Expr::MethodCall(call) => {
                self.references.insert(call.method.to_string());
            }
            Expr::Macro(macro_call) => {
                if let Some(segment) = macro_call.mac.path.segments.last() {
                    self.references.insert(segment.ident.to_string());
                }
            }
            _ => {}
        }
        visit::visit_expr(self, expression);
    }
}

fn read_git_regular_bytes(root: &Path, revision: &str, relative: &str) -> Result<Vec<u8>, String> {
    validate_relative_path("git source path", relative)?;
    let tree = git_output(root, &["ls-tree", "-z", revision, "--", relative])?;
    let entry = tree
        .strip_suffix(&[0])
        .ok_or_else(|| format!("git tree entry missing for {revision}:{relative}"))?;
    if entry.contains(&0) {
        return Err(format!(
            "multiple git tree entries for {revision}:{relative}"
        ));
    }
    let entry = std::str::from_utf8(entry)
        .map_err(|error| format!("git tree entry for {relative} is not UTF-8: {error}"))?;
    let (metadata, found_path) = entry
        .split_once('\t')
        .ok_or_else(|| format!("malformed git tree entry for {revision}:{relative}"))?;
    let mut metadata = metadata.split_whitespace();
    let mode = metadata.next().unwrap_or_default();
    let kind = metadata.next().unwrap_or_default();
    let object = metadata.next().unwrap_or_default();
    if found_path != relative || kind != "blob" || !matches!(mode, "100644" | "100755") {
        return Err(format!(
            "git source must be a regular non-symlink blob at {revision}:{relative}"
        ));
    }
    if object.len() != 40 && object.len() != 64 {
        return Err(format!("malformed git object id for {revision}:{relative}"));
    }
    git_output(root, &["show", &format!("{revision}:{relative}")])
}

fn require_ancestor_revision(root: &Path, revision: &str) -> Result<(), String> {
    let status = Command::new("git")
        .current_dir(root)
        .args(["merge-base", "--is-ancestor", revision, "HEAD"])
        .status()
        .map_err(|error| format!("run git merge-base for {revision}: {error}"))?;
    if !status.success() {
        return Err(format!(
            "evidence revision {revision} is missing or is not an ancestor of HEAD"
        ));
    }
    Ok(())
}

fn git_output(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(arguments)
        .output()
        .map_err(|error| format!("run git {}: {error}", arguments.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn read_regular_bytes(root: &Path, relative: &str) -> Result<Vec<u8>, String> {
    validate_relative_path("path", relative)?;
    let path = root.join(relative);
    let metadata =
        fs::symlink_metadata(&path).map_err(|error| format!("inspect {relative}: {error}"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "path must be a regular non-symlink file: {relative}"
        ));
    }
    let first = fs::read(&path).map_err(|error| format!("read {relative}: {error}"))?;
    let second = fs::read(&path).map_err(|error| format!("reread {relative}: {error}"))?;
    if first != second {
        return Err(format!("file changed while reading: {relative}"));
    }
    Ok(first)
}

fn validate_relative_path(field: &str, value: &str) -> Result<(), String> {
    require_nonempty(field, value)?;
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || value.contains(':')
        || value.contains('\\')
    {
        return Err(format!(
            "{field} must be a normalized repository-relative path: {value}"
        ));
    }
    Ok(())
}

fn validate_symbol_name(field: &str, value: &str) -> Result<(), String> {
    require_nonempty(field, value)?;
    if value
        .split("::")
        .any(|segment| !is_rust_identifier(segment))
    {
        return Err(format!("{field} must be an exact Rust symbol path"));
    }
    Ok(())
}

fn is_rust_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn require_digest(field: &str, bytes: &[u8], expected: &str) -> Result<(), String> {
    require_sha256(&format!("{field} sha256"), expected)?;
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected {
        return Err(format!(
            "{field} byte digest drifted: expected {expected}, found {actual}"
        ));
    }
    Ok(())
}

fn require_sha256(field: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err(format!("{field} must be a lowercase SHA-256"));
    }
    Ok(())
}

fn require_full_revision(field: &str, value: &str) -> Result<(), String> {
    if value.len() != 40
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err(format!("{field} must be a full lowercase Git SHA"));
    }
    Ok(())
}

fn require_eq(field: &str, actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{field} must be {expected}, found {actual}"))
    }
}

fn require_nonempty(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.trim() != value {
        Err(format!("{field} must be nonempty and trimmed"))
    } else {
        Ok(())
    }
}

fn require_token(field: &str, value: &str) -> Result<(), String> {
    require_nonempty(field, value)?;
    if value
        .bytes()
        .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
    {
        return Err(format!("{field} must be a lowercase kebab token"));
    }
    Ok(())
}

fn require_exact_list(field: &str, actual: &[String], expected: &[&str]) -> Result<(), String> {
    if actual.len() != expected.len()
        || actual
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual != expected)
    {
        return Err(format!("{field} must equal {expected:?}"));
    }
    Ok(())
}

fn require_date(field: &str, value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return Err(format!("{field} must be YYYY-MM-DD"));
    }
    let year = value[0..4].parse::<u32>().unwrap_or(0);
    let month = value[5..7].parse::<u32>().unwrap_or(0);
    let day = value[8..10].parse::<u32>().unwrap_or(0);
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days {
        return Err(format!("{field} is not a valid date"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn fixture() -> (Overlay, BaseMatrix) {
        let overlay = fs::read_to_string(root().join(OVERLAY_PATH)).unwrap();
        let matrix = fs::read_to_string(root().join(BASE_MATRIX_PATH)).unwrap();
        (
            toml::from_str(&overlay).unwrap(),
            toml::from_str(&matrix).unwrap(),
        )
    }

    fn head() -> String {
        String::from_utf8(git_output(&root(), &["rev-parse", "HEAD"]).unwrap())
            .unwrap()
            .trim()
            .to_owned()
    }

    fn mapped_promotion() -> Promotion {
        Promotion {
            sequence: 1,
            cell_id: "qdp-reservation-failure-before-hardware".into(),
            tranche: "queue-dma-preparation".into(),
            boundary: "queue-dma-preparation".into(),
            from: "planned".into(),
            to: "source-mapped".into(),
            classification: ROOT_OWNED_OBLIGATION.into(),
            recorded_on: "2026-07-19".into(),
            source_mapping: Some(SourceMapping {
                revision: head(),
                production: SourceSymbol {
                    path: "tools/xtask/src/causal_fault_matrix.rs".into(),
                    symbol: "validate".into(),
                },
                normal_callsite: SourceSymbol {
                    path: "tools/xtask/src/main.rs".into(),
                    symbol: "check".into(),
                },
                injection: SourceSymbol {
                    path: "tools/xtask/src/causal_fault_matrix.rs".into(),
                    symbol: "validate_document".into(),
                },
            }),
            observation: None,
        }
    }

    fn promote_once(overlay: &mut Overlay) {
        overlay.promotion.push(mapped_promotion());
        overlay.promotion_count = 1;
        overlay.planned_count = 65;
        overlay.source_mapped_count = 1;
        overlay.status = STATUS_PROGRESS.into();
    }

    #[test]
    fn repository_overlay_is_empty_incomplete_and_byte_freezes_both_v1_inputs() {
        let summary = validate(&root()).unwrap();
        assert_eq!(summary.cells, 66);
        assert_eq!(summary.promotions, 0);
        assert_eq!(summary.planned, 66);
        assert_eq!(summary.source_mapped, 0);
        assert_eq!(summary.observed, 0);
        assert!(!summary.complete);

        let coverage = fs::read(root().join(BASE_COVERAGE_PATH)).unwrap();
        require_digest(BASE_COVERAGE_PATH, &coverage, BASE_COVERAGE_SHA256).unwrap();
        let matrix = fs::read(root().join(BASE_MATRIX_PATH)).unwrap();
        require_digest(BASE_MATRIX_PATH, &matrix, BASE_MATRIX_SHA256).unwrap();
    }

    #[test]
    fn accepts_exact_adjacent_source_mapping_and_rejects_skip_or_duplicate() {
        let repository = root();
        let (mut overlay, base) = fixture();
        promote_once(&mut overlay);
        let summary = validate_document(&repository, &overlay, &base).unwrap();
        assert_eq!(summary.source_mapped, 1);

        let (mut skipped, base) = fixture();
        let mut promotion = mapped_promotion();
        promotion.to = "observed".into();
        promotion.source_mapping = None;
        skipped.promotion.push(promotion);
        skipped.promotion_count = 1;
        skipped.planned_count = 65;
        skipped.observed_count = 1;
        skipped.status = STATUS_PROGRESS.into();
        let error = validate_document(&repository, &skipped, &base).unwrap_err();
        assert!(error.contains("may only advance"));

        let (mut duplicate, base) = fixture();
        promote_once(&mut duplicate);
        let mut again = mapped_promotion();
        again.sequence = 2;
        duplicate.promotion.push(again);
        duplicate.promotion_count = 2;
        let error = validate_document(&repository, &duplicate, &base).unwrap_err();
        assert!(error.contains("non-monotonic or duplicate"));
    }

    #[test]
    fn rejects_unknown_renamed_or_reordered_promotion_identity() {
        let repository = root();
        let (mut unknown, base) = fixture();
        let mut promotion = mapped_promotion();
        promotion.cell_id = "fabricated-causal-cell".into();
        unknown.promotion.push(promotion);
        unknown.promotion_count = 1;
        unknown.planned_count = 65;
        unknown.source_mapped_count = 1;
        unknown.status = STATUS_PROGRESS.into();
        let error = validate_document(&repository, &unknown, &base).unwrap_err();
        assert!(error.contains("unknown or renamed"));

        let (mut renamed, base) = fixture();
        let mut promotion = mapped_promotion();
        promotion.boundary = "renamed-boundary".into();
        renamed.promotion.push(promotion);
        renamed.promotion_count = 1;
        renamed.planned_count = 65;
        renamed.source_mapped_count = 1;
        renamed.status = STATUS_PROGRESS.into();
        let error = validate_document(&repository, &renamed, &base).unwrap_err();
        assert!(error.contains("frozen tranche/boundary"));

        let (mut reordered, base) = fixture();
        let mut promotion = mapped_promotion();
        promotion.sequence = 2;
        reordered.promotion.push(promotion);
        reordered.promotion_count = 1;
        reordered.planned_count = 65;
        reordered.source_mapped_count = 1;
        reordered.status = STATUS_PROGRESS.into();
        let error = validate_document(&repository, &reordered, &base).unwrap_err();
        assert!(error.contains("sequence must be 1"));
    }

    #[test]
    fn source_mapping_rejects_missing_symbols_and_test_only_callsite() {
        let repository = root();
        let mut mapping = mapped_promotion().source_mapping.unwrap();
        mapping.production.symbol = "fabricated_missing_symbol".into();
        let error = validate_source_mapping(&repository, "cell", &mapping).unwrap_err();
        assert!(error.contains("is missing"));

        let mut mapping = mapped_promotion().source_mapping.unwrap();
        mapping.normal_callsite = SourceSymbol {
            path: "tools/xtask/src/causal_fault_matrix.rs".into(),
            symbol: "tests::repository_causal_matrix_is_exactly_planned_and_freezes_legacy_bytes"
                .into(),
        };
        let error = validate_source_mapping(&repository, "cell", &mapping).unwrap_err();
        assert!(error.contains("test-only"));

        let self_test = SourceSymbol {
            path: "kernel/nexus-ostd/src/cser/effect_registry.rs".into(),
            symbol: "production_identity_registry_self_test".into(),
        };
        let bytes = read_regular_bytes(&repository, &self_test.path).unwrap();
        let symbols = parse_symbols(&self_test.path, &bytes).unwrap();
        let error =
            validate_mapped_symbol("cell", "normal_callsite", &self_test, &symbols).unwrap_err();
        assert!(error.contains("test-only"));
    }

    #[test]
    fn source_mapping_rejects_missing_and_symlink_source_paths() {
        let repository = root();
        let mut mapping = mapped_promotion().source_mapping.unwrap();
        mapping.production.path = "tools/xtask/src/missing-causal-source.rs".into();
        let error = validate_source_mapping(&repository, "cell", &mapping).unwrap_err();
        assert!(error.contains("inspect"));

        let temporary = temporary_path("symlink-source");
        fs::create_dir_all(&temporary).unwrap();
        let relative_directory = temporary.strip_prefix(&repository).ok();
        if let Some(relative_directory) = relative_directory {
            fs::write(temporary.join("real.rs"), "fn production() {}\n").unwrap();
            symlink("real.rs", temporary.join("link.rs")).unwrap();
            let mut mapping = mapped_promotion().source_mapping.unwrap();
            mapping.production.path = relative_directory.join("link.rs").display().to_string();
            let error = validate_source_mapping(&repository, "cell", &mapping).unwrap_err();
            assert!(error.contains("regular non-symlink"));
        }
        let _ = fs::remove_dir_all(temporary);
    }

    #[test]
    fn static_gate_requires_normal_to_production_to_injection_edges() {
        let repository = root();
        let mut mapping = mapped_promotion().source_mapping.unwrap();
        mapping.injection = SourceSymbol {
            path: "tools/xtask/src/causal_fault_matrix.rs".into(),
            symbol: "validate_projection".into(),
        };
        let error = validate_source_mapping(&repository, "cell", &mapping).unwrap_err();
        assert!(error.contains("production -> injection"));
    }

    #[test]
    fn observation_binds_mapping_revision_artifact_and_receipt() {
        let repository = root();
        let temporary = temporary_path("observation");
        fs::create_dir_all(&temporary).unwrap();
        let relative = temporary.strip_prefix(&repository).unwrap();
        let artifact_path = relative.join("qemu.log").display().to_string();
        let receipt_path = relative.join("receipt.json").display().to_string();
        let revision = head();
        let schema = "nexus.causal-cell-observation-receipt.v1";
        let artifact = b"bounded qemu artifact\n";
        let receipt = format!(
            "{{\"schema\":\"{schema}\",\"cell_id\":\"qdp-reservation-failure-before-hardware\",\"revision\":\"{revision}\"}}\n"
        );
        fs::write(repository.join(&artifact_path), artifact).unwrap();
        fs::write(repository.join(&receipt_path), receipt.as_bytes()).unwrap();

        let observation = Observation {
            revision: revision.clone(),
            qemu_profile: "nexus-ostd-qemu-one-vcpu".into(),
            qemu_artifact_path: artifact_path,
            qemu_artifact_sha256: format!("{:x}", Sha256::digest(artifact)),
            receipt_path,
            receipt_sha256: format!("{:x}", Sha256::digest(receipt.as_bytes())),
            receipt_schema: schema.into(),
        };
        let mapping = mapped_promotion().source_mapping.unwrap();
        validate_observation(
            &repository,
            "qdp-reservation-failure-before-hardware",
            &mapping,
            &observation,
        )
        .unwrap();

        let (mut overlay, base) = fixture();
        promote_once(&mut overlay);
        overlay.promotion.push(Promotion {
            sequence: 2,
            cell_id: "qdp-reservation-failure-before-hardware".into(),
            tranche: "queue-dma-preparation".into(),
            boundary: "queue-dma-preparation".into(),
            from: "source-mapped".into(),
            to: "observed".into(),
            classification: ROOT_OWNED_OBLIGATION.into(),
            recorded_on: "2026-07-19".into(),
            source_mapping: None,
            observation: Some(observation.clone()),
        });
        overlay.promotion_count = 2;
        overlay.source_mapped_count = 0;
        overlay.observed_count = 1;
        let summary = validate_document(&repository, &overlay, &base).unwrap();
        assert_eq!(summary.observed, 1);

        let mut revision_drift = observation.clone();
        revision_drift.revision = "0000000000000000000000000000000000000000".into();
        let error = validate_observation(
            &repository,
            "qdp-reservation-failure-before-hardware",
            &mapping,
            &revision_drift,
        )
        .unwrap_err();
        assert!(error.contains("revision drift"));

        let mut artifact_drift = observation;
        artifact_drift.qemu_artifact_sha256 = "0".repeat(64);
        let error = validate_observation(
            &repository,
            "qdp-reservation-failure-before-hardware",
            &mapping,
            &artifact_drift,
        )
        .unwrap_err();
        assert!(error.contains("byte digest drifted"));

        let mut receipt_drift = artifact_drift;
        receipt_drift.qemu_artifact_sha256 = format!("{:x}", Sha256::digest(artifact));
        receipt_drift.receipt_sha256 = "0".repeat(64);
        let error = validate_observation(
            &repository,
            "qdp-reservation-failure-before-hardware",
            &mapping,
            &receipt_drift,
        )
        .unwrap_err();
        assert!(error.contains("receipt byte digest drifted"));
        fs::remove_dir_all(temporary).unwrap();
    }

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        root().join("target/xtask-tests").join(format!(
            "causal-evidence-{label}-{}-{nonce}",
            std::process::id()
        ))
    }
}
