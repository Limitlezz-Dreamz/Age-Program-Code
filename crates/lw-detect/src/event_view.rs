use lw_core::NormalizedEvent;
use lw_rules::LogsourceMapping;
use serde_json::{json, Map, Value};

/// Build a flat JSON object suitable for rsigma `JsonEvent`.
pub fn event_to_json(event: &NormalizedEvent, mapping: &LogsourceMapping) -> Value {
    let mut map = Map::new();
    // Preserve normalized fields first.
    for (k, v) in &event.fields {
        map.insert(k.clone(), v.clone());
    }
    // Ensure canonical top-level keys used by built-ins / Sigma.
    map.insert("Channel".into(), Value::String(event.channel.clone()));
    map.insert("EventID".into(), json!(event.event_id));
    map.insert(
        "Provider_Name".into(),
        Value::String(event.provider.clone()),
    );
    map.insert("Computer".into(), Value::String(event.computer.clone()));
    map.insert("EventRecordID".into(), json!(event.record_id));
    // DB row id for correlation EventRef linking (`id` is first lookup key).
    map.insert("id".into(), Value::String(event.id.to_string()));
    // Epoch seconds for CorrelationEngine timestamp extraction (never wall-clock).
    map.insert("@timestamp".into(), json!(event.ts / 1_000_000));

    // Logsource dimensions for rsigma pruning.
    map.insert("product".into(), Value::String("windows".into()));
    let services = mapping.services_for(&event.channel);
    if let Some(svc) = services.first() {
        map.insert("service".into(), Value::String(svc.clone()));
    }
    let cats = mapping.categories_for(&event.channel, event.event_id);
    if let Some(cat) = cats.first() {
        map.insert("category".into(), Value::String(cat.clone()));
    }
    if let Some(user) = &event.user_name {
        map.entry("TargetUserName".to_string())
            .or_insert_with(|| Value::String(user.clone()));
    }
    if let Some(ip) = &event.src_ip {
        map.entry("IpAddress".to_string())
            .or_insert_with(|| Value::String(ip.clone()));
    }
    if let Some(lt) = event.logon_type {
        map.entry("LogonType".to_string())
            .or_insert_with(|| json!(lt));
    }
    Value::Object(map)
}
