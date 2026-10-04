use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct FieldAliasRule {
    pub when: BTreeMap<String, Value>,
    pub add: BTreeMap<String, String>,
}

/// Load field alias rules from YAML (our own format).
pub fn load_field_aliases(path: impl AsRef<Path>) -> lw_core::Result<Vec<FieldAliasRule>> {
    let text = std::fs::read_to_string(path)?;
    let rules: Vec<FieldAliasRule> = serde_yaml::from_str(&text)
        .map_err(|e| lw_core::Error::msg(format!("aliases yaml: {e}")))?;
    Ok(rules)
}

/// Apply alias rules as *additional* keys; originals are never removed.
pub fn apply_aliases(fields: &mut Map<String, Value>, rules: &[FieldAliasRule]) {
    let mut to_add: Vec<(String, Value)> = Vec::new();
    for rule in rules {
        if !matches_when(fields, &rule.when) {
            continue;
        }
        for (dest, template) in &rule.add {
            if let Some(v) = render_template(template, fields) {
                to_add.push((dest.clone(), v));
            }
        }
    }
    for (k, v) in to_add {
        fields.entry(k).or_insert(v);
    }
}

fn matches_when(fields: &Map<String, Value>, when: &BTreeMap<String, Value>) -> bool {
    for (k, expected) in when {
        let Some(actual) = fields.get(k) else {
            return false;
        };
        if !values_equal(actual, expected) {
            return false;
        }
    }
    true
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(n), Value::String(s)) | (Value::String(s), Value::Number(n)) => {
            s.parse::<f64>().ok() == n.as_f64()
        }
        _ => a == b,
    }
}

fn render_template(template: &str, fields: &Map<String, Value>) -> Option<Value> {
    // Simple `{FieldName}` substitution; if the whole template is one field, preserve type.
    if template.starts_with('{') && template.ends_with('}') && template.matches('{').count() == 1 {
        let key = &template[1..template.len() - 1];
        return fields.get(key).cloned();
    }
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let end = rest[start..].find('}')?.saturating_add(start);
        out.push_str(&rest[..start]);
        let key = &rest[start + 1..end];
        let piece = fields.get(key).map(value_as_string).unwrap_or_default();
        out.push_str(&piece);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(Value::String(out))
}

fn value_as_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Built-in Security 4688 aliases when no YAML is loaded.
pub fn default_4688_aliases() -> Vec<FieldAliasRule> {
    let yaml = r#"
- when: { Channel: Security, EventID: 4688 }
  add:
    Image: "{NewProcessName}"
    ParentImage: "{ParentProcessName}"
    User: "{SubjectDomainName}\\{SubjectUserName}"
"#;
    serde_yaml::from_str(yaml).unwrap_or_default()
}
