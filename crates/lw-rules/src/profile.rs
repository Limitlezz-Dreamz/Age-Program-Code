use crate::load::{LoadedRule, RuleBody};
use lw_core::Severity;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleProfile {
    /// status ∈ {stable, test}, level ≥ medium, exclude deprecated/unsupported
    #[default]
    Default,
    All,
    HighCritical,
}

impl RuleProfile {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "default" => Some(Self::Default),
            "all" => Some(Self::All),
            "high" | "high+critical" | "highcritical" => Some(Self::HighCritical),
            _ => None,
        }
    }
}

pub fn filter_rules(rules: Vec<LoadedRule>, profile: RuleProfile) -> (Vec<LoadedRule>, u64) {
    let before = rules.len() as u64;
    let mut kept: Vec<LoadedRule> = Vec::new();
    let mut kept_ids: HashSet<String> = HashSet::new();

    for r in &rules {
        if profile_keeps(r, profile) {
            if let Some(id) = r.sigma_id() {
                kept_ids.insert(id.to_string());
            }
            kept.push(r.clone());
        }
    }

    // Retain base rules referenced by kept correlations (even if informational).
    let mut needed: HashSet<String> = HashSet::new();
    for r in &kept {
        if let RuleBody::Correlation(corr) = &r.body {
            for ref_id in &corr.rules {
                if !kept_ids.contains(ref_id) {
                    needed.insert(ref_id.clone());
                }
            }
        }
    }
    if !needed.is_empty() {
        for r in &rules {
            if let Some(id) = r.sigma_id() {
                if needed.contains(id) && !kept_ids.contains(id) {
                    // Still exclude deprecated/unsupported deps.
                    if matches!(r.status.as_deref(), Some("deprecated" | "unsupported")) {
                        continue;
                    }
                    kept_ids.insert(id.to_string());
                    kept.push(r.clone());
                }
            }
        }
    }

    let skipped = before.saturating_sub(kept.len() as u64);
    (kept, skipped)
}

fn profile_keeps(r: &LoadedRule, profile: RuleProfile) -> bool {
    match profile {
        RuleProfile::All => !matches!(r.status.as_deref(), Some("deprecated" | "unsupported")),
        RuleProfile::Default => {
            let status_ok = matches!(r.status.as_deref(), None | Some("stable") | Some("test"));
            let level_ok = r.severity >= Severity::Medium;
            let not_dead = !matches!(r.status.as_deref(), Some("deprecated" | "unsupported"));
            status_ok && level_ok && not_dead && !r.unmapped
        }
        RuleProfile::HighCritical => {
            r.severity >= Severity::High
                && !matches!(r.status.as_deref(), Some("deprecated" | "unsupported"))
                && !r.unmapped
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::{find_builtins_dir, find_mapping_path, load_builtins};
    use crate::mapping::load_logsource_mapping;

    #[test]
    fn default_keeps_correlation_bases() {
        let mapping = load_logsource_mapping(find_mapping_path().unwrap()).unwrap();
        let set = load_builtins(find_builtins_dir().unwrap(), &mapping).unwrap();
        let (kept, _) = filter_rules(set.rules, RuleProfile::Default);
        assert!(
            kept.iter().any(|r| r.id.as_deref() == Some("B010")),
            "B010 correlation"
        );
        assert!(
            kept.iter().any(|r| r.id.as_deref() == Some("B010-base")),
            "B010-base retained as dependency"
        );
    }
}
