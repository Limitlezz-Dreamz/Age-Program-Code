use lw_core::MitreRef;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Deserialize)]
struct AttackEntry {
    name: String,
    #[serde(default)]
    tactic: Option<String>,
}

static ATTACK: OnceLock<HashMap<String, AttackEntry>> = OnceLock::new();

pub fn load_attack_json(path: impl AsRef<Path>) -> lw_core::Result<()> {
    let text = fs::read_to_string(path)?;
    let map: HashMap<String, AttackEntry> =
        serde_json::from_str(&text).map_err(|e| lw_core::Error::msg(e.to_string()))?;
    let _ = ATTACK.set(map);
    Ok(())
}

fn attack_map() -> &'static HashMap<String, AttackEntry> {
    ATTACK.get_or_init(|| {
        for p in [
            "resources/mitre/attack.json",
            "../resources/mitre/attack.json",
            "../../resources/mitre/attack.json",
        ] {
            if let Ok(text) = fs::read_to_string(p) {
                if let Ok(map) = serde_json::from_str(&text) {
                    return map;
                }
            }
        }
        HashMap::new()
    })
}

/// Parse Sigma `tags` into MITRE technique/tactic refs.
pub fn parse_mitre_tags(tags: &[String]) -> Vec<MitreRef> {
    let map = attack_map();
    let mut out = Vec::new();
    let mut tactics: Vec<String> = Vec::new();
    let mut techniques: Vec<(String, Option<String>)> = Vec::new();

    for tag in tags {
        let t = tag.to_ascii_lowercase();
        if let Some(rest) = t.strip_prefix("attack.t") {
            if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                let tech = format!("T{}", rest.to_ascii_uppercase());
                let key = format!("t{}", rest);
                let name = map.get(&key).map(|e| e.name.clone());
                techniques.push((tech, name));
                continue;
            }
        }
        if let Some(rest) = t.strip_prefix("attack.") {
            // tactic names: credential-access / credential_access
            let normalized = rest.replace('_', "-");
            if !normalized.is_empty()
                && !normalized.chars().next().unwrap().is_ascii_digit()
                && !normalized.starts_with('t')
            {
                tactics.push(normalized);
            }
        }
    }

    if techniques.is_empty() && tactics.is_empty() {
        return out;
    }

    if techniques.is_empty() {
        for tactic in tactics {
            out.push(MitreRef {
                technique: None,
                tactic: Some(tactic),
                name: None,
            });
        }
        return out;
    }

    for (tech, name) in techniques {
        let tactic = map
            .get(&tech.to_ascii_lowercase())
            .and_then(|e| e.tactic.clone())
            .or_else(|| tactics.first().cloned());
        out.push(MitreRef {
            technique: Some(tech),
            tactic,
            name,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_technique_and_tactic() {
        let refs = parse_mitre_tags(&["attack.t1070.001".into(), "attack.defense_evasion".into()]);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].technique.as_deref(), Some("T1070.001"));
        assert_eq!(refs[0].tactic.as_deref(), Some("defense-evasion"));
    }
}
