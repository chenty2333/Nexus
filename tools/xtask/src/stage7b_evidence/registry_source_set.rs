use quote::ToTokens;
use std::collections::BTreeMap;
use std::path::Path;

/// Logical ownership units for the production Registry source.
///
/// The current production layout intentionally activates only `Authority`.
/// Naming the future units here lets the evidence gate reject cross-file moves
/// and duplicates before the monolith is mechanically split. Activating a new
/// unit remains an explicit evidence change: its path must be added to
/// `CURRENT_UNITS` and every moved checked item must change owner in
/// `CHECKED_ITEM_OWNERSHIP` in the same commit.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum RegistryUnit {
    Authority,
    Identity,
    Core,
    CausalTransaction,
    Recovery,
    Device,
    Handoff,
    Projection,
    Evidence,
    Invariants,
}

impl RegistryUnit {
    const ALL: [Self; 10] = [
        Self::Authority,
        Self::Identity,
        Self::Core,
        Self::CausalTransaction,
        Self::Recovery,
        Self::Device,
        Self::Handoff,
        Self::Projection,
        Self::Evidence,
        Self::Invariants,
    ];

    pub(super) const fn path(self) -> &'static str {
        match self {
            Self::Authority => "kernel/nexus-ostd/src/cser/effect_registry.rs",
            Self::Identity => "kernel/nexus-ostd/src/cser/effect_registry/identity.rs",
            Self::Core => "kernel/nexus-ostd/src/cser/effect_registry/core.rs",
            Self::CausalTransaction => {
                "kernel/nexus-ostd/src/cser/effect_registry/causal_transaction.rs"
            }
            Self::Recovery => "kernel/nexus-ostd/src/cser/effect_registry/recovery.rs",
            Self::Device => "kernel/nexus-ostd/src/cser/effect_registry/device.rs",
            Self::Handoff => "kernel/nexus-ostd/src/cser/effect_registry/handoff.rs",
            Self::Projection => "kernel/nexus-ostd/src/cser/effect_registry/projection.rs",
            Self::Evidence => "kernel/nexus-ostd/src/cser/effect_registry/evidence.rs",
            Self::Invariants => "kernel/nexus-ostd/src/cser/effect_registry/invariants.rs",
        }
    }
}

const CURRENT_UNITS: &[RegistryUnit] = &[RegistryUnit::Authority];

/// The task/fault self-tests and the direct production call which admits them
/// currently live in the authority source. This coordinate will move to
/// `Evidence` only when that source exists and its complete owner-map update is
/// reviewed in the same change.
pub(super) const TASK_FAULT_EVIDENCE_UNIT: RegistryUnit = RegistryUnit::Authority;

#[derive(Debug)]
pub(super) struct RegistrySourceSet {
    sources: BTreeMap<RegistryUnit, String>,
}

impl RegistrySourceSet {
    pub(super) fn read_current(root: &Path) -> Result<Self, String> {
        let mut sources = BTreeMap::new();
        for unit in RegistryUnit::ALL {
            let active = CURRENT_UNITS.contains(&unit);
            let source = super::read_regular(root, unit.path(), !active)?;
            let Some(source) = source else {
                if active {
                    return Err(format!(
                        "required Stage 7B Registry source is missing: {}",
                        unit.path()
                    ));
                }
                continue;
            };
            if !active {
                return Err(format!(
                    "inactive Stage 7B Registry unit exists before its owner-map activation: {unit:?} ({})",
                    unit.path()
                ));
            }
            if sources.insert(unit, source).is_some() {
                return Err(format!("Stage 7B Registry layout duplicates unit {unit:?}"));
            }
        }
        Ok(Self { sources })
    }

    #[cfg(test)]
    pub(super) fn from_authority(source: &str) -> Self {
        Self {
            sources: BTreeMap::from([(RegistryUnit::Authority, source.to_owned())]),
        }
    }

    pub(super) fn source(&self, unit: RegistryUnit) -> Result<&str, String> {
        self.sources.get(&unit).map(String::as_str).ok_or_else(|| {
            format!(
                "Stage 7B Registry source set lacks required {unit:?} unit: {}",
                unit.path()
            )
        })
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (RegistryUnit, &str)> {
        self.sources
            .iter()
            .map(|(unit, source)| (*unit, source.as_str()))
    }

    #[cfg(test)]
    pub(super) fn for_test(
        entries: impl IntoIterator<Item = (RegistryUnit, String)>,
    ) -> Result<Self, String> {
        let mut sources = BTreeMap::new();
        for (unit, source) in entries {
            if source.is_empty() {
                return Err(format!("Stage 7B Registry test unit {unit:?} is empty"));
            }
            if sources.insert(unit, source).is_some() {
                return Err(format!(
                    "Stage 7B Registry source set duplicates unit {unit:?}"
                ));
            }
        }
        if !sources.contains_key(&RegistryUnit::Authority) {
            return Err("Stage 7B Registry source set lacks its Authority unit".into());
        }
        Ok(Self { sources })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckedItemKind {
    Struct,
    Enum,
    Function,
    RegistryMethod,
}

#[derive(Clone, Copy, Debug)]
struct CheckedItemOwner {
    kind: CheckedItemKind,
    name: &'static str,
    owner: RegistryUnit,
}

const fn owned(kind: CheckedItemKind, name: &'static str, owner: RegistryUnit) -> CheckedItemOwner {
    CheckedItemOwner { kind, name, owner }
}

/// Exact owners for the authority declaration and representative checked
/// items at every future module seam. This is deliberately not inferred from
/// file names: moving an item requires an explicit reviewable owner change.
const CHECKED_ITEM_OWNERSHIP: &[CheckedItemOwner] = &[
    owned(
        CheckedItemKind::Struct,
        "EffectRegistry",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Enum,
        "RegistryError",
        RegistryUnit::Authority,
    ),
    owned(CheckedItemKind::Struct, "ScopeKey", RegistryUnit::Authority),
    owned(
        CheckedItemKind::Struct,
        "CreditLedger",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Struct,
        "CombinedScopeCandidate",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Struct,
        "RecoverySnapshot",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Struct,
        "DeviceBatchCommitReceipt",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Enum,
        "HandoffFreezeReadiness",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Struct,
        "RegistryProjection",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Struct,
        "Stage7bFaultBudget",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::RegistryMethod,
        "new",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::RegistryMethod,
        "register_in_domain",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::RegistryMethod,
        "prepare_service_fault_disposition",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::RegistryMethod,
        "install_service_fault_disposition",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::RegistryMethod,
        "clone_non_device_candidate",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::RegistryMethod,
        "crash",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::RegistryMethod,
        "commit_device_batch_with_publish",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::RegistryMethod,
        "freeze_admission",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::RegistryMethod,
        "scope_projection",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::RegistryMethod,
        "check_invariants",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Function,
        "task_owned_fault_outer_transaction_self_test",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Function,
        "ordinary_domain_crash_rejects_a_forged_fault_origin",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Function,
        "device_preparation_outer_credit_self_test",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Function,
        "device_preparation_outer_materialization_self_test",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Function,
        "supervisor_domain_recovery_primitives_self_test",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Function,
        "production_identity_registry_self_test",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Function,
        "production_device_batch_registry_self_test",
        RegistryUnit::Authority,
    ),
    owned(
        CheckedItemKind::Function,
        "retained_semantic_test_fixture",
        RegistryUnit::Authority,
    ),
];

#[derive(Clone, Copy)]
struct AllowedRegistryHolder {
    owner: RegistryUnit,
    item: &'static str,
    field: &'static str,
}

const ALLOWED_REGISTRY_HOLDERS: &[AllowedRegistryHolder] = &[
    // The device materialization transaction is a private, synchronous,
    // allocation-bearing fallback. `base` is immutable stale-candidate
    // evidence and `candidate` is installed at most once; neither field is
    // exposed as caller authority. The O(N) shape remains an explicit
    // non-claim until a preallocated per-scope transaction replaces it.
    AllowedRegistryHolder {
        owner: RegistryUnit::Authority,
        item: "DeviceCohortMaterializationPlan",
        field: "base",
    },
    AllowedRegistryHolder {
        owner: RegistryUnit::Authority,
        item: "DeviceCohortMaterializationPlan",
        field: "candidate",
    },
    AllowedRegistryHolder {
        owner: RegistryUnit::Authority,
        item: "DeviceDerivedCohortPlan",
        field: "candidate",
    },
    AllowedRegistryHolder {
        owner: RegistryUnit::Authority,
        item: "CombinedScopeCandidate",
        field: "replacement",
    },
    AllowedRegistryHolder {
        owner: RegistryUnit::Authority,
        item: "Stage7bFaultBudget",
        field: "registry",
    },
    AllowedRegistryHolder {
        owner: RegistryUnit::Authority,
        item: "Stage7bFaultBudgetState",
        field: "registry",
    },
    AllowedRegistryHolder {
        owner: RegistryUnit::Authority,
        item: "Stage7bActiveFixture",
        field: "registry",
    },
    AllowedRegistryHolder {
        owner: RegistryUnit::Authority,
        item: "Stage7bCompleteFixture",
        field: "registry",
    },
    AllowedRegistryHolder {
        owner: RegistryUnit::Authority,
        item: "ProductionDeviceBatchRaceFixture",
        field: "registry",
    },
];

pub(super) fn validate_source_set(sources: &RegistrySourceSet) -> Result<(), String> {
    let known_paths = RegistryUnit::ALL
        .into_iter()
        .map(RegistryUnit::path)
        .collect::<std::collections::BTreeSet<_>>();
    if known_paths.len() != RegistryUnit::ALL.len() {
        return Err("Stage 7B Registry unit paths are not unique".into());
    }
    sources.source(RegistryUnit::Authority)?;
    let parsed = sources
        .iter()
        .map(|(unit, source)| {
            syn::parse_file(source)
                .map(|syntax| (unit, syntax))
                .map_err(|error| {
                    format!(
                        "Stage 7B Registry unit {unit:?} does not parse independently ({}): {error}",
                        unit.path()
                    )
                })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    validate_checked_item_ownership(&parsed)?;
    validate_single_authority(&parsed)?;
    validate_registry_holders(&parsed)
}

fn validate_checked_item_ownership(
    parsed: &BTreeMap<RegistryUnit, syn::File>,
) -> Result<(), String> {
    for checked in CHECKED_ITEM_OWNERSHIP {
        let observed = parsed
            .iter()
            .filter_map(|(unit, syntax)| {
                let count = checked_item_count(syntax, checked.kind, checked.name);
                (count != 0).then_some((*unit, count))
            })
            .collect::<Vec<_>>();
        if observed.as_slice() != [(checked.owner, 1)] {
            return Err(format!(
                "Stage 7B Registry checked-item ownership drifted for {:?} {}: expected {:?}=1, observed={observed:?}",
                checked.kind, checked.name, checked.owner
            ));
        }
    }
    Ok(())
}

fn checked_item_count(syntax: &syn::File, kind: CheckedItemKind, name: &str) -> usize {
    match kind {
        CheckedItemKind::Struct => syntax
            .items
            .iter()
            .filter(|item| matches!(item, syn::Item::Struct(item) if item.ident == name))
            .count(),
        CheckedItemKind::Enum => syntax
            .items
            .iter()
            .filter(|item| matches!(item, syn::Item::Enum(item) if item.ident == name))
            .count(),
        CheckedItemKind::Function => syntax
            .items
            .iter()
            .filter(|item| matches!(item, syn::Item::Fn(item) if item.sig.ident == name))
            .count(),
        CheckedItemKind::RegistryMethod => syntax
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Impl(item_impl)
                    if exact_type_path(&item_impl.self_ty, "EffectRegistry") =>
                {
                    Some(item_impl)
                }
                _ => None,
            })
            .flat_map(|item_impl| &item_impl.items)
            .filter(|item| matches!(item, syn::ImplItem::Fn(method) if method.sig.ident == name))
            .count(),
    }
}

fn validate_single_authority(parsed: &BTreeMap<RegistryUnit, syn::File>) -> Result<(), String> {
    let mut registry_definitions = Vec::new();
    let mut clone_impls = Vec::new();
    for (unit, syntax) in parsed {
        for item in &syntax.items {
            let reserved_name = match item {
                syn::Item::Const(item) => Some(&item.ident),
                syn::Item::Enum(item) => Some(&item.ident),
                syn::Item::Fn(item) => Some(&item.sig.ident),
                syn::Item::Mod(item) => Some(&item.ident),
                syn::Item::Static(item) => Some(&item.ident),
                syn::Item::Struct(item) => Some(&item.ident),
                syn::Item::Trait(item) => Some(&item.ident),
                syn::Item::TraitAlias(item) => Some(&item.ident),
                syn::Item::Type(item) => Some(&item.ident),
                syn::Item::Union(item) => Some(&item.ident),
                _ => None,
            };
            if reserved_name.is_some_and(|ident| ident == "EffectRegistry") {
                registry_definitions.push((*unit, item_kind(item)));
            }

            let syn::Item::Impl(item_impl) = item else {
                continue;
            };
            if exact_type_path(&item_impl.self_ty, "EffectRegistry")
                && item_impl.trait_.as_ref().is_some_and(|(_, path, _)| {
                    path.segments
                        .last()
                        .is_some_and(|segment| segment.ident == "Clone")
                })
            {
                clone_impls.push(*unit);
            }
        }
    }
    if registry_definitions.as_slice() != [(RegistryUnit::Authority, "struct")] {
        return Err(format!(
            "Stage 7B Registry must retain exactly one authoritative struct declaration in Authority; observed={registry_definitions:?}"
        ));
    }
    if !clone_impls.is_empty() {
        return Err(format!(
            "Stage 7B Registry authority must not implement Clone in any source unit; observed={clone_impls:?}"
        ));
    }
    Ok(())
}

fn validate_registry_holders(parsed: &BTreeMap<RegistryUnit, syn::File>) -> Result<(), String> {
    for (unit, syntax) in parsed {
        for item in &syntax.items {
            match item {
                syn::Item::Struct(item_struct) => {
                    validate_fields(*unit, &item_struct.ident.to_string(), &item_struct.fields)?
                }
                syn::Item::Enum(item_enum) => {
                    for variant in &item_enum.variants {
                        validate_fields(
                            *unit,
                            &format!("{}::{}", item_enum.ident, variant.ident),
                            &variant.fields,
                        )?;
                    }
                }
                syn::Item::Union(item_union) => {
                    for field in &item_union.fields.named {
                        validate_field(
                            *unit,
                            &item_union.ident.to_string(),
                            field.ident.as_ref().map(ToString::to_string),
                            &field.ty,
                        )?;
                    }
                }
                syn::Item::Type(item_type)
                    if token_identifier_count(item_type.ty.to_token_stream(), "EffectRegistry")
                        != 0 =>
                {
                    return Err(format!(
                        "Stage 7B Registry rejects authority type alias {} in unit {unit:?}",
                        item_type.ident
                    ));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn validate_fields(unit: RegistryUnit, item: &str, fields: &syn::Fields) -> Result<(), String> {
    for (index, field) in fields.iter().enumerate() {
        validate_field(
            unit,
            item,
            field
                .ident
                .as_ref()
                .map(ToString::to_string)
                .or_else(|| Some(index.to_string())),
            &field.ty,
        )?;
    }
    Ok(())
}

fn validate_field(
    unit: RegistryUnit,
    item: &str,
    field: Option<String>,
    field_type: &syn::Type,
) -> Result<(), String> {
    if token_identifier_count(field_type.to_token_stream(), "EffectRegistry") == 0 {
        return Ok(());
    }
    let field = field.unwrap_or_else(|| "<unnamed>".to_owned());
    let allowed = ALLOWED_REGISTRY_HOLDERS
        .iter()
        .any(|allowed| allowed.owner == unit && allowed.item == item && allowed.field == field);
    if !allowed {
        return Err(format!(
            "Stage 7B Registry rejects unapproved authority wrapper/holder {unit:?}::{item}.{field}"
        ));
    }
    Ok(())
}

fn exact_type_path(ty: &syn::Type, expected: &str) -> bool {
    matches!(
        ty,
        syn::Type::Path(path)
            if path.qself.is_none()
                && path.path.segments.len() == 1
                && path.path.segments[0].ident == expected
                && matches!(path.path.segments[0].arguments, syn::PathArguments::None)
    )
}

fn token_identifier_count(tokens: proc_macro2::TokenStream, name: &str) -> usize {
    tokens
        .into_iter()
        .map(|token| match token {
            proc_macro2::TokenTree::Ident(ident) => usize::from(ident == name),
            proc_macro2::TokenTree::Group(group) => token_identifier_count(group.stream(), name),
            proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => 0,
        })
        .sum()
}

fn item_kind(item: &syn::Item) -> &'static str {
    match item {
        syn::Item::Const(_) => "const",
        syn::Item::Enum(_) => "enum",
        syn::Item::Fn(_) => "function",
        syn::Item::Mod(_) => "module",
        syn::Item::Static(_) => "static",
        syn::Item::Struct(_) => "struct",
        syn::Item::Trait(_) => "trait",
        syn::Item::TraitAlias(_) => "trait alias",
        syn::Item::Type(_) => "type alias",
        syn::Item::Union(_) => "union",
        _ => "other",
    }
}
