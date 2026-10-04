use lw_core::{Error, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct LogsourceMapping {
    /// category -> list of (channel, event_ids)
    pub categories: HashMap<String, Vec<(String, Vec<u32>)>>,
    /// service -> channels
    pub services: HashMap<String, Vec<String>>,
    /// reverse: (channel, event_id) -> categories
    reverse_category: HashMap<(String, u32), Vec<String>>,
    /// reverse: channel -> services
    reverse_service: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RawMapping {
    #[serde(default)]
    categories: HashMap<String, Vec<RawCond>>,
    #[serde(default)]
    services: HashMap<String, ServiceVal>,
}

#[derive(Debug, Deserialize)]
struct RawCond {
    #[serde(rename = "Channel")]
    channel: ChannelVal,
    #[serde(rename = "EventID")]
    event_id: EventIdVal,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ChannelVal {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EventIdVal {
    One(u32),
    Many(Vec<u32>),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ServiceVal {
    One(String),
    Many(Vec<String>),
}

pub fn load_logsource_mapping(path: impl AsRef<Path>) -> Result<LogsourceMapping> {
    let text = std::fs::read_to_string(path)?;
    let raw: RawMapping =
        serde_yaml::from_str(&text).map_err(|e| Error::msg(format!("logsource yaml: {e}")))?;
    let mut m = LogsourceMapping::default();
    for (cat, conds) in raw.categories {
        let mut list = Vec::new();
        for c in conds {
            let channels = match c.channel {
                ChannelVal::One(s) => vec![s],
                ChannelVal::Many(v) => v,
            };
            let eids = match c.event_id {
                EventIdVal::One(n) => vec![n],
                EventIdVal::Many(v) => v,
            };
            for ch in channels {
                list.push((ch.clone(), eids.clone()));
                for eid in &eids {
                    m.reverse_category
                        .entry((ch.clone(), *eid))
                        .or_default()
                        .push(cat.clone());
                }
            }
        }
        m.categories.insert(cat, list);
    }
    for (svc, val) in raw.services {
        let channels = match val {
            ServiceVal::One(s) => vec![s],
            ServiceVal::Many(v) => v,
        };
        for ch in &channels {
            m.reverse_service
                .entry(ch.clone())
                .or_default()
                .push(svc.clone());
        }
        m.services.insert(svc, channels);
    }
    Ok(m)
}

impl LogsourceMapping {
    pub fn categories_for(&self, channel: &str, event_id: u32) -> Vec<String> {
        self.reverse_category
            .get(&(channel.to_string(), event_id))
            .cloned()
            .unwrap_or_default()
    }

    pub fn services_for(&self, channel: &str) -> Vec<String> {
        self.reverse_service
            .get(channel)
            .cloned()
            .unwrap_or_default()
    }

    pub fn is_category_mapped(&self, category: &str) -> bool {
        self.categories.contains_key(category)
    }

    pub fn is_service_mapped(&self, service: &str) -> bool {
        self.services.contains_key(service)
    }

    pub fn known_categories(&self) -> HashSet<&str> {
        self.categories.keys().map(String::as_str).collect()
    }
}
