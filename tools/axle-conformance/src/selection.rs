use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow};

use crate::model::{ProfileSpec, ScenarioSpec};

/// Apply profile and CLI filters to produce an ordered scenario list.
pub fn select_scenarios(
    scenarios: &BTreeMap<String, ScenarioSpec>,
    profile: Option<&ProfileSpec>,
    scenario_filters: &[String],
    tag_filters: &[String],
) -> Result<Vec<ScenarioSpec>> {
    let mut selected_ids: BTreeSet<String> = scenarios.keys().cloned().collect();

    if let Some(p) = profile {
        if !p.include_tags.is_empty() {
            selected_ids.retain(|id| {
                scenarios
                    .get(id)
                    .is_some_and(|scenario| scenario.has_any_tag(&p.include_tags))
            });
        }

        for id in &p.include_ids {
            if scenarios.contains_key(id) {
                selected_ids.insert(id.clone());
            }
        }

        if !p.exclude_tags.is_empty() {
            selected_ids.retain(|id| {
                scenarios
                    .get(id)
                    .is_some_and(|scenario| !scenario.has_any_tag(&p.exclude_tags))
            });
        }

        for id in &p.exclude_ids {
            selected_ids.remove(id);
        }
    }

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
        }
    }

    #[test]
    fn profile_include_and_exclude_tags_work() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), scenario("a", &["tier:quick", "module:port"]));
        map.insert("b".into(), scenario("b", &["tier:slow", "module:timer"]));

        let profile = ProfileSpec {
            include_tags: vec!["tier:quick".into()],
            exclude_tags: vec!["module:timer".into()],
            include_ids: vec![],
            exclude_ids: vec![],
        };

        let out = select_scenarios(&map, Some(&profile), &[], &[]).expect("selection");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "a");
    }

    #[test]
    fn cli_tag_filter_is_all_tags_match() {
        let mut map = BTreeMap::new();
        map.insert("a".into(), scenario("a", &["module:port", "tier:quick"]));
        map.insert("b".into(), scenario("b", &["module:port"]));

        let out = select_scenarios(
            &map,
            None,
            &[],
            &["module:port".into(), "tier:quick".into()],
        )
        .expect("selection");

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "a");
    }
}
