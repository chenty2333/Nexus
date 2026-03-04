use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow};

use crate::model::ScenarioSpec;

/// Apply CLI filters to produce an ordered scenario list.
pub fn select_scenarios(
    scenarios: &BTreeMap<String, ScenarioSpec>,
    scenario_filters: &[String],
    tag_filters: &[String],
) -> Result<Vec<ScenarioSpec>> {
    let mut selected_ids: BTreeSet<String> = scenarios.keys().cloned().collect();

    if !scenario_filters.is_empty() {
        for id in scenario_filters {
            if !scenarios.contains_key(id) {
                return Err(anyhow!("unknown scenario id '{}': not found", id));
            }
        }
        selected_ids.retain(|id| scenario_filters.iter().any(|requested| requested == id));
    }

    if !tag_filters.is_empty() {
        selected_ids.retain(|id| {
            scenarios
                .get(id)
                .is_some_and(|scenario| scenario.has_all_tags(tag_filters))
        });
    }

    let mut ordered = Vec::with_capacity(selected_ids.len());
    for id in selected_ids {
        if let Some(s) = scenarios.get(&id) {
            ordered.push(s.clone());
        }
    }
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario(id: &str, tags: &[&str]) -> ScenarioSpec {
        ScenarioSpec {
            id: id.to_string(),
            description: String::new(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            timeout_ms: 100,
            command: vec!["true".to_string()],
            expect: vec![],
            forbid: vec![],
            contracts: vec![],
            assertions: None,
            elf_check: None,
        }
    }

    #[test]
    fn scenario_filter_by_id_works() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), scenario("a", &["module:port", "kind:qemu"]));
        map.insert("b".into(), scenario("b", &["module:timer", "kind:qemu"]));

        let out = select_scenarios(&map, &["a".into()], &[]).expect("selection");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "a");
    }

    #[test]
    fn cli_tag_filter_is_all_tags_match() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), scenario("a", &["module:port", "kind:qemu"]));
        map.insert("b".into(), scenario("b", &["module:port"]));

        let out = select_scenarios(&map, &[], &["module:port".into(), "kind:qemu".into()])
            .expect("selection");

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "a");
    }
}
