use quote::ToTokens;
use std::collections::BTreeMap;
use syn::visit::Visit;

const TASK_TEST: &str = "task_owned_fault_outer_transaction_self_test";
const ORDINARY_TEST: &str = "ordinary_domain_crash_rejects_a_forged_fault_origin";
const PRODUCTION_TEST: &str = "production_identity_registry_self_test";

#[derive(Default)]
struct SourceAudit {
    registry_constructors: usize,
    function_calls: BTreeMap<String, usize>,
    macros: Vec<(String, String)>,
}

impl SourceAudit {
    fn function_calls(&self, name: &str) -> usize {
        self.function_calls.get(name).copied().unwrap_or_default()
    }

    fn macro_calls(&self, path: &str, tokens: proc_macro2::TokenStream) -> usize {
        let tokens = tokens.to_string();
        self.macros
            .iter()
            .filter(|(observed_path, observed_tokens)| {
                observed_path == path && observed_tokens == &tokens
            })
            .count()
    }
}

impl<'ast> Visit<'ast> for SourceAudit {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            let path = canonical_path(&path.path);
            if path == "EffectRegistry::new" && call.args.is_empty() {
                self.registry_constructors += 1;
            }
            *self.function_calls.entry(path).or_default() += 1;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_macro(&mut self, source_macro: &'ast syn::Macro) {
        self.macros.push((
            canonical_path(&source_macro.path),
            source_macro.tokens.to_string(),
        ));
        syn::visit::visit_macro(self, source_macro);
    }
}

pub(super) fn validate_and_count_registry_constructors(source: &str) -> Result<usize, String> {
    let syntax = syn::parse_file(source)
        .map_err(|error| format!("Stage 7B Registry source does not parse: {error}"))?;
    let count = audit_file(&syntax).registry_constructors;
    validate_task_fault_self_tests(&syntax)?;
    Ok(count)
}

fn canonical_path(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn audit_file(syntax: &syn::File) -> SourceAudit {
    let mut audit = SourceAudit::default();
    audit.visit_file(syntax);
    audit
}

fn audit_function(function: &syn::ItemFn) -> SourceAudit {
    let mut audit = SourceAudit::default();
    audit.visit_item_fn(function);
    audit
}

fn exact_top_level_function<'a>(
    syntax: &'a syn::File,
    name: &str,
    label: &str,
) -> Result<&'a syn::ItemFn, String> {
    let functions = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    if functions.len() != 1 {
        return Err(format!(
            "{label} must remain exactly one top-level function, observed {}",
            functions.len()
        ));
    }
    Ok(functions[0])
}

fn is_exact_cfg_test(attribute: &syn::Attribute) -> bool {
    matches!(
        &attribute.meta,
        syn::Meta::List(list)
            if list.path.is_ident("cfg") && list.tokens.to_string() == "test"
    )
}

fn validate_zero_argument_private_test_function(
    function: &syn::ItemFn,
    label: &str,
) -> Result<(), String> {
    if function.attrs.len() != 1
        || !is_exact_cfg_test(&function.attrs[0])
        || !matches!(function.vis, syn::Visibility::Inherited)
        || function.sig.constness.is_some()
        || function.sig.asyncness.is_some()
        || function.sig.unsafety.is_some()
        || function.sig.abi.is_some()
        || !function.sig.generics.params.is_empty()
        || function.sig.generics.where_clause.is_some()
        || !function.sig.inputs.is_empty()
        || !matches!(function.sig.output, syn::ReturnType::Default)
    {
        return Err(format!(
            "{label} must remain one private zero-argument #[cfg(test)] self-test"
        ));
    }
    Ok(())
}

fn direct_cfg_test_call_count(function: &syn::ItemFn, name: &str) -> usize {
    function
        .block
        .stmts
        .iter()
        .filter(|statement| {
            let syn::Stmt::Expr(syn::Expr::Call(call), Some(_)) = statement else {
                return false;
            };
            let syn::Expr::Path(path) = call.func.as_ref() else {
                return false;
            };
            path.path.is_ident(name)
                && call.args.is_empty()
                && call.attrs.len() == 1
                && is_exact_cfg_test(&call.attrs[0])
        })
        .count()
}

fn direct_registry_constructor_count(function: &syn::ItemFn) -> usize {
    function
        .block
        .stmts
        .iter()
        .filter(|statement| {
            let syn::Stmt::Local(local) = statement else {
                return false;
            };
            let syn::Pat::Ident(pattern) = &local.pat else {
                return false;
            };
            let Some(initializer) = &local.init else {
                return false;
            };
            let syn::Expr::Call(call) = initializer.expr.as_ref() else {
                return false;
            };
            let syn::Expr::Path(path) = call.func.as_ref() else {
                return false;
            };
            local.attrs.is_empty()
                && pattern.attrs.is_empty()
                && pattern.by_ref.is_none()
                && pattern.mutability.is_some()
                && pattern.ident == "registry"
                && pattern.subpat.is_none()
                && initializer.diverge.is_none()
                && call.attrs.is_empty()
                && call.args.is_empty()
                && canonical_path(&path.path) == "EffectRegistry::new"
        })
        .count()
}

fn direct_macro_count(
    function: &syn::ItemFn,
    path: &str,
    tokens: &proc_macro2::TokenStream,
) -> usize {
    let tokens = tokens.to_string();
    function
        .block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            syn::Stmt::Macro(statement_macro)
                if statement_macro.attrs.is_empty() && statement_macro.semi_token.is_some() =>
            {
                Some(&statement_macro.mac)
            }
            syn::Stmt::Expr(syn::Expr::Macro(expression_macro), Some(_))
                if expression_macro.attrs.is_empty() =>
            {
                Some(&expression_macro.mac)
            }
            _ => None,
        })
        .filter(|source_macro| {
            canonical_path(&source_macro.path) == path && source_macro.tokens.to_string() == tokens
        })
        .count()
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

fn require_identifier_population(
    function: &syn::ItemFn,
    expected: &[(&str, usize)],
    label: &str,
) -> Result<(), String> {
    let tokens = function.to_token_stream();
    for (identifier, expected_count) in expected {
        let observed = token_identifier_count(tokens.clone(), identifier);
        if observed != *expected_count {
            return Err(format!(
                "{label} checked call population drifted for {identifier}: expected {expected_count}, observed {observed}"
            ));
        }
    }
    Ok(())
}

fn require_exact_direct_macro(
    function: &syn::ItemFn,
    audit: &SourceAudit,
    path: &str,
    tokens: proc_macro2::TokenStream,
    label: &str,
) -> Result<(), String> {
    let observed = audit.macro_calls(path, tokens.clone());
    let direct = direct_macro_count(function, path, &tokens);
    if observed != 1 || direct != 1 {
        return Err(format!(
            "{label} must remain one exact direct self-test assertion, observed total={observed} direct={direct}"
        ));
    }
    Ok(())
}

fn validate_task_fault_self_tests(syntax: &syn::File) -> Result<(), String> {
    let task = exact_top_level_function(syntax, TASK_TEST, "task-owned fault self-test")?;
    let ordinary = exact_top_level_function(
        syntax,
        ORDINARY_TEST,
        "ordinary domain-crash origin self-test",
    )?;
    let production = exact_top_level_function(
        syntax,
        PRODUCTION_TEST,
        "production-identity Registry self-test",
    )?;
    validate_zero_argument_private_test_function(task, "task-owned fault self-test")?;
    validate_zero_argument_private_test_function(
        ordinary,
        "ordinary domain-crash origin self-test",
    )?;

    let nested = task
        .block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            syn::Stmt::Item(syn::Item::Fn(function)) => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    if nested.len() != 1 || nested[0].sig.ident != "fixture" {
        return Err(
            "task-owned fault self-test must retain exactly one function-local fixture".into(),
        );
    }
    let fixture_audit = audit_function(nested[0]);
    let task_audit = audit_function(task);
    let direct_fixture_registries = direct_registry_constructor_count(nested[0]);
    if fixture_audit.registry_constructors != 1
        || task_audit.registry_constructors != 1
        || direct_fixture_registries != 1
    {
        return Err(format!(
            "task-owned fault self-test must directly own exactly one Registry in its fixture (fixture={}, function={}, direct={direct_fixture_registries})",
            fixture_audit.registry_constructors, task_audit.registry_constructors,
        ));
    }
    if task_audit.function_calls("fixture") != 3 {
        return Err(format!(
            "task-owned fault self-test must exercise its exact stale/crash/isolate fixture population, observed {} calls",
            task_audit.function_calls("fixture")
        ));
    }
    require_identifier_population(
        task,
        &[
            ("prepare_service_fault_disposition", 4),
            ("install_service_fault_disposition", 3),
            ("claim_fault_receipt", 5),
            ("check_invariants", 9),
        ],
        "task-owned fault self-test",
    )?;
    for (path, tokens, label) in [
        (
            "__cser_core::assert_eq",
            quote::quote!(
                stale_failure.error(),
                &RegistryError::CombinedCandidateStale
            ),
            "task-owned stale-candidate error assertion",
        ),
        (
            "__cser_core::assert_eq",
            quote::quote!(stale, stale_before),
            "task-owned stale-candidate failure atomicity assertion",
        ),
        (
            "__cser_core::assert",
            quote::quote!(__cser_core::matches!(
                recovery.origin,
                DomainRecoveryOrigin::ServiceFault(_)
            )),
            "task-owned exact service-fault origin assertion",
        ),
        (
            "__cser_core::assert_eq",
            quote::quote!(
                missing_fault_origin.check_invariants(),
                Err(RegistryError::Invariant("domain recovery origin mismatch"))
            ),
            "task-owned forged-origin rejection assertion",
        ),
        (
            "__cser_core::assert_eq",
            quote::quote!(missing_fault_origin, before),
            "task-owned forged-origin failure atomicity assertion",
        ),
    ] {
        require_exact_direct_macro(task, &task_audit, path, tokens, label)?;
    }

    let ordinary_nested = ordinary
        .block
        .stmts
        .iter()
        .filter(|statement| matches!(statement, syn::Stmt::Item(syn::Item::Fn(_))))
        .count();
    let ordinary_audit = audit_function(ordinary);
    let direct_ordinary_registries = direct_registry_constructor_count(ordinary);
    if ordinary_nested != 0
        || ordinary_audit.registry_constructors != 1
        || direct_ordinary_registries != 1
    {
        return Err(format!(
            "ordinary domain-crash origin self-test must directly own exactly one Registry and no hidden function (constructors={}, direct={}, nested_functions={ordinary_nested})",
            ordinary_audit.registry_constructors, direct_ordinary_registries,
        ));
    }
    require_identifier_population(
        ordinary,
        &[("crash_domain", 1), ("check_invariants", 2)],
        "ordinary domain-crash origin self-test",
    )?;
    for (path, tokens, label) in [
        (
            "__cser_core::assert_eq",
            quote::quote!(
                registry.scopes[&SCOPE].domains[&SERVICE]
                    .recovery
                    .as_ref()
                    .unwrap()
                    .origin,
                DomainRecoveryOrigin::SupervisorCrash
            ),
            "ordinary domain-crash exact supervisor origin assertion",
        ),
        (
            "__cser_core::assert_eq",
            quote::quote!(
                forged.check_invariants(),
                Err(RegistryError::Invariant("domain recovery origin mismatch"))
            ),
            "ordinary domain-crash forged-origin rejection assertion",
        ),
        (
            "__cser_core::assert_eq",
            quote::quote!(forged, before),
            "ordinary domain-crash forged-origin failure atomicity assertion",
        ),
    ] {
        require_exact_direct_macro(ordinary, &ordinary_audit, path, tokens, label)?;
    }

    let production_audit = audit_function(production);
    let source_audit = audit_file(syntax);
    for (name, label) in [
        (TASK_TEST, "task-owned fault self-test"),
        (ORDINARY_TEST, "ordinary domain-crash origin self-test"),
    ] {
        if direct_cfg_test_call_count(production, name) != 1
            || production_audit.function_calls(name) != 1
            || source_audit.function_calls(name) != 1
        {
            return Err(format!(
                "{label} must be called exactly once as a direct #[cfg(test)] production-identity self-test step"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn reject_mutation(source: &str, mutated: &str, label: &str, expected_error: &str) {
    assert_ne!(mutated, source, "missing mutation fixture for {label}");
    let syntax = syn::parse_file(mutated)
        .unwrap_or_else(|error| panic!("{label} mutation must remain valid Rust: {error}"));
    let error = validate_task_fault_self_tests(&syntax)
        .expect_err("task/fault self-test mutation unexpectedly passed");
    assert!(
        error.contains(expected_error),
        "task/fault mutation {label:?} failed through the wrong gate: {error}"
    );
}

#[cfg(test)]
pub(super) fn exercise_negative_mutations(source: &str) {
    let task_constructor_error =
        "task-owned fault self-test must directly own exactly one Registry";
    let ordinary_constructor_error =
        "ordinary domain-crash origin self-test must directly own exactly one Registry";
    let call_error = "must be called exactly once as a direct #[cfg(test)]";

    let moved_task_constructor = source
        .replacen(
            concat!(
                "        infrastructure::ArmedFaultTask,\n",
                "        EffectKey,\n",
                "    ) {\n",
                "        let mut registry = EffectRegistry::new();",
            ),
            concat!(
                "        infrastructure::ArmedFaultTask,\n",
                "        EffectKey,\n",
                "    ) {\n",
                "        let mut registry = EffectRegistry::default();",
            ),
            1,
        )
        .replacen(
            "pub(crate) struct Stage7bFaultCredit {",
            "fn hidden_task_fault_sidecar() -> EffectRegistry { EffectRegistry::new() }\n\npub(crate) struct Stage7bFaultCredit {",
            1,
        );
    assert_eq!(
        moved_task_constructor
            .matches("EffectRegistry::new()")
            .count(),
        source.matches("EffectRegistry::new()").count(),
    );
    reject_mutation(
        source,
        &moved_task_constructor,
        "task constructor moved to a hidden sidecar",
        task_constructor_error,
    );

    let moved_ordinary_constructor = source
        .replacen(
            "    const SERVICE_OWNER: TaskKey = TaskKey::new(0xfd11, 1);\n\n    let mut registry = EffectRegistry::new();",
            "    const SERVICE_OWNER: TaskKey = TaskKey::new(0xfd11, 1);\n\n    let mut registry = EffectRegistry::default();",
            1,
        )
        .replacen(
            "pub(crate) struct Stage7bFaultCredit {",
            "fn hidden_ordinary_crash_sidecar() -> EffectRegistry { EffectRegistry::new() }\n\npub(crate) struct Stage7bFaultCredit {",
            1,
        );
    assert_eq!(
        moved_ordinary_constructor
            .matches("EffectRegistry::new()")
            .count(),
        source.matches("EffectRegistry::new()").count(),
    );
    reject_mutation(
        source,
        &moved_ordinary_constructor,
        "ordinary constructor moved to a hidden sidecar",
        ordinary_constructor_error,
    );

    for (call, replacement, label) in [
        (
            "    #[cfg(test)]\n    task_owned_fault_outer_transaction_self_test();\n",
            "",
            "deleted task-owned self-test call",
        ),
        (
            "    #[cfg(test)]\n    ordinary_domain_crash_rejects_a_forged_fault_origin();\n",
            "",
            "deleted ordinary self-test call",
        ),
        (
            "    #[cfg(test)]\n    task_owned_fault_outer_transaction_self_test();\n",
            "    #[cfg(test)]\n    if false {\n        task_owned_fault_outer_transaction_self_test();\n    }\n",
            "task-owned self-test call moved under if false",
        ),
        (
            "    #[cfg(test)]\n    ordinary_domain_crash_rejects_a_forged_fault_origin();\n",
            "    #[cfg(test)]\n    if false {\n        ordinary_domain_crash_rejects_a_forged_fault_origin();\n    }\n",
            "ordinary self-test call moved under if false",
        ),
    ] {
        reject_mutation(
            source,
            &source.replacen(call, replacement, 1),
            label,
            call_error,
        );
    }

    for (needle, replacement, label, expected_error) in [
        (
            "        let mut registry = EffectRegistry::new();\n        registry\n            .create_scope(ScopeConfig {\n                key: SCOPE,",
            "        let mut registry = EffectRegistry::new();\n        let _duplicate_registry = EffectRegistry::new();\n        registry\n            .create_scope(ScopeConfig {\n                key: SCOPE,",
            "duplicated task-owned Registry",
            task_constructor_error,
        ),
        (
            "        infrastructure::ArmedFaultTask,\n        EffectKey,\n    ) {\n        let mut registry = EffectRegistry::new();",
            "        infrastructure::ArmedFaultTask,\n        EffectKey,\n    ) {\n        let mut registry = { EffectRegistry::new() };",
            "task Registry constructor moved into a nested expression",
            task_constructor_error,
        ),
        (
            "    const SERVICE_OWNER: TaskKey = TaskKey::new(0xfd11, 1);\n\n    let mut registry = EffectRegistry::new();",
            "    const SERVICE_OWNER: TaskKey = TaskKey::new(0xfd11, 1);\n\n    let mut registry = EffectRegistry::new();\n    let _duplicate_registry = EffectRegistry::new();",
            "duplicated ordinary crash Registry",
            ordinary_constructor_error,
        ),
    ] {
        reject_mutation(
            source,
            &source.replacen(needle, replacement, 1),
            label,
            expected_error,
        );
    }

    let task_origin = concat!(
        "__cser_core::assert!(__cser_core::matches!(\n",
        "        recovery.origin,\n",
        "        DomainRecoveryOrigin::ServiceFault(_)\n",
        "    ));",
    );
    let ordinary_origin = concat!(
        "__cser_core::assert_eq!(\n",
        "        registry.scopes[&SCOPE].domains[&SERVICE]\n",
        "            .recovery\n",
        "            .as_ref()\n",
        "            .unwrap()\n",
        "            .origin,\n",
        "        DomainRecoveryOrigin::SupervisorCrash\n",
        "    );",
    );
    for (needle, replacement, label, expected_error) in [
        (
            "&RegistryError::CombinedCandidateStale",
            "&RegistryError::InvalidState",
            "weakened exact stale-candidate error",
            "task-owned stale-candidate error assertion",
        ),
        (
            "__cser_core::assert_eq!(stale, stale_before);",
            "let _ = stale_before;",
            "deleted stale-candidate failure atomicity assertion",
            "task-owned stale-candidate failure atomicity assertion",
        ),
        (
            "__cser_core::assert_eq!(stale, stale_before);",
            "let _deferred = || { __cser_core::assert_eq!(stale, stale_before); };",
            "stale-candidate atomicity assertion moved into a closure",
            "task-owned stale-candidate failure atomicity assertion",
        ),
        (
            "__cser_core::assert_eq!(stale, stale_before);",
            "#[cfg(any())]\n    __cser_core::assert_eq!(stale, stale_before);",
            "stale-candidate atomicity assertion conditionally removed",
            "task-owned stale-candidate failure atomicity assertion",
        ),
        (
            task_origin,
            "__cser_core::assert!(recovery.crash_revision > 0);",
            "weakened exact service-fault origin assertion",
            "task-owned exact service-fault origin assertion",
        ),
        (
            task_origin,
            "if false { __cser_core::assert!(__cser_core::matches!(recovery.origin, DomainRecoveryOrigin::ServiceFault(_))); }",
            "service-fault origin assertion moved under if false",
            "task-owned exact service-fault origin assertion",
        ),
        (
            "__cser_core::assert_eq!(missing_fault_origin, before);",
            "let _ = before;",
            "deleted forged service-fault origin atomicity assertion",
            "task-owned forged-origin failure atomicity assertion",
        ),
        (
            ordinary_origin,
            "__cser_core::assert!(registry.scopes[&SCOPE].domains[&SERVICE].recovery.is_some());",
            "weakened exact ordinary supervisor-crash origin assertion",
            "ordinary domain-crash exact supervisor origin assertion",
        ),
        (
            ordinary_origin,
            "if false { __cser_core::assert_eq!(registry.scopes[&SCOPE].domains[&SERVICE].recovery.as_ref().unwrap().origin, DomainRecoveryOrigin::SupervisorCrash); }",
            "ordinary supervisor-crash origin assertion moved under if false",
            "ordinary domain-crash exact supervisor origin assertion",
        ),
        (
            "__cser_core::assert_eq!(forged, before);",
            "let _ = before;",
            "deleted ordinary forged-origin atomicity assertion",
            "ordinary domain-crash forged-origin failure atomicity assertion",
        ),
        (
            "__cser_core::assert_eq!(forged, before);",
            "let _deferred = || { __cser_core::assert_eq!(forged, before); };",
            "ordinary forged-origin atomicity assertion moved into a closure",
            "ordinary domain-crash forged-origin failure atomicity assertion",
        ),
    ] {
        reject_mutation(
            source,
            &source.replacen(needle, replacement, 1),
            label,
            expected_error,
        );
    }

    for (needle, replacement, label, expected_error) in [
        (
            "        missing_fault_origin.check_invariants(),\n        Err(RegistryError::Invariant(\"domain recovery origin mismatch\"))",
            "        missing_fault_origin.check_invariants(),\n        Err(RegistryError::InvalidState)",
            "weakened exact forged service-fault origin error",
            "task-owned forged-origin rejection assertion",
        ),
        (
            "        forged.check_invariants(),\n        Err(RegistryError::Invariant(\"domain recovery origin mismatch\"))",
            "        forged.check_invariants(),\n        Err(RegistryError::InvalidState)",
            "weakened exact forged ordinary-origin error",
            "ordinary domain-crash forged-origin rejection assertion",
        ),
    ] {
        reject_mutation(
            source,
            &source.replacen(needle, replacement, 1),
            label,
            expected_error,
        );
    }
}
