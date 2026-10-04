use crate::mapping::LogsourceMapping;
use lw_core::{Error, Result, RuleSource, Severity};
use rsigma_parser::{parse_sigma_yaml, CorrelationRule, Level, SigmaCollection, SigmaRule, Status};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub enum RuleBody {
    Detection(SigmaRule),
    Correlation(CorrelationRule),
}

#[derive(Debug, Clone)]
pub struct LoadedRule {
    pub uid: String,
    pub title: String,
    pub id: Option<String>,
    pub author: Option<String>,
    pub severity: Severity,
    pub status: Option<String>,
    pub tags: Vec<String>,
    pub yaml: String,
    pub source: RuleSource,
    pub unmapped: bool,
    pub body: RuleBody,
}

impl LoadedRule {
    pub fn is_correlation(&self) -> bool {
        matches!(self.body, RuleBody::Correlation(_))
    }

    pub fn sigma_id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

#[derive(Debug, Clone, Default)]
pub struct LoadReport {
    pub total_files: u64,
    pub total_rules: u64,
    pub loaded: u64,
    pub skipped_profile: u64,
    pub unmapped: u64,
    pub parse_errors: u64,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<LoadedRule>,
    pub filters: Vec<rsigma_parser::FilterRule>,
    pub report: LoadReport,
}

impl RuleSet {
    pub fn merge(&mut self, other: RuleSet) {
        self.report.total_files += other.report.total_files;
        self.report.total_rules += other.report.total_rules;
        self.report.loaded += other.report.loaded;
        self.report.skipped_profile += other.report.skipped_profile;
        self.report.unmapped += other.report.unmapped;
        self.report.parse_errors += other.report.parse_errors;
        self.report.errors.extend(other.report.errors);
        self.rules.extend(other.rules);
        self.filters.extend(other.filters);
    }

    pub fn to_collection(&self) -> SigmaCollection {
        let mut c = SigmaCollection::new();
        for r in &self.rules {
            match &r.body {
                RuleBody::Detection(rule) => c.rules.push(rule.clone()),
                RuleBody::Correlation(corr) => c.correlations.push(corr.clone()),
            }
        }
        c.filters = self.filters.clone();
        c
    }
}

pub fn load_builtins(dir: impl AsRef<Path>, mapping: &LogsourceMapping) -> Result<RuleSet> {
    load_rules_from_dir(dir, "builtin", "0.1.0", RuleSource::Builtin, mapping)
}

pub fn load_rules_from_dir(
    dir: impl AsRef<Path>,
    pack: &str,
    version: &str,
    source_template: RuleSource,
    mapping: &LogsourceMapping,
) -> Result<RuleSet> {
    let mut set = RuleSet::default();
    if !dir.as_ref().is_dir() {
        return Err(Error::msg(format!(
            "rules directory not found: {}",
            dir.as_ref().display()
        )));
    }
    for entry in WalkDir::new(dir.as_ref())
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if ext != "yml" && ext != "yaml" {
            continue;
        }
        set.report.total_files += 1;
        let yaml = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                set.report.parse_errors += 1;
                set.report.errors.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        append_yaml(
            &mut set,
            &yaml,
            path,
            pack,
            version,
            &source_template,
            mapping,
        );
    }
    Ok(set)
}

pub fn load_rules_from_zip(
    zip_path: impl AsRef<Path>,
    pack: &str,
    version: &str,
    url: Option<String>,
    mapping: &LogsourceMapping,
) -> Result<RuleSet> {
    let file = fs::File::open(zip_path.as_ref())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| Error::msg(format!("zip: {e}")))?;
    let mut set = RuleSet::default();
    let source = RuleSource::Sigma {
        pack: pack.to_string(),
        version: version.to_string(),
        path: zip_path.as_ref().display().to_string(),
        url,
    };
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| Error::msg(format!("zip entry: {e}")))?;
        let name = file.name().to_string();
        if file.is_dir() {
            continue;
        }
        if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }
        set.report.total_files += 1;
        let mut yaml = String::new();
        if let Err(e) = file.read_to_string(&mut yaml) {
            set.report.parse_errors += 1;
            set.report.errors.push(format!("{name}: {e}"));
            continue;
        }
        append_yaml(
            &mut set,
            &yaml,
            Path::new(&name),
            pack,
            version,
            &source,
            mapping,
        );
    }
    Ok(set)
}

fn append_yaml(
    set: &mut RuleSet,
    yaml: &str,
    path: &Path,
    pack: &str,
    version: &str,
    source_template: &RuleSource,
    mapping: &LogsourceMapping,
) {
    match parse_sigma_yaml(yaml) {
        Ok(collection) => {
            for err in &collection.errors {
                set.report.parse_errors += 1;
                set.report.errors.push(format!("{}: {err}", path.display()));
            }
            set.filters.extend(collection.filters.iter().cloned());
            for rule in &collection.rules {
                push_detection(
                    set,
                    rule,
                    yaml,
                    path,
                    pack,
                    version,
                    source_template,
                    mapping,
                );
            }
            for corr in &collection.correlations {
                push_correlation(set, corr, yaml, path, pack, version, source_template);
            }
        }
        Err(e) => {
            set.report.parse_errors += 1;
            set.report.errors.push(format!("{}: {e}", path.display()));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_detection(
    set: &mut RuleSet,
    rule: &SigmaRule,
    yaml: &str,
    path: &Path,
    pack: &str,
    version: &str,
    source_template: &RuleSource,
    mapping: &LogsourceMapping,
) {
    set.report.total_rules += 1;
    if !is_windows_rule(rule) {
        return;
    }

    let unmapped = is_unmapped(rule, mapping);
    if unmapped {
        set.report.unmapped += 1;
    }

    let id = rule.id.clone().unwrap_or_else(|| {
        format!(
            "{}",
            blake3::hash(path.as_os_str().as_encoded_bytes()).to_hex()
        )
    });
    let uid = format!("{pack}:{id}");
    let severity = rule
        .level
        .as_ref()
        .map(level_to_severity)
        .unwrap_or(Severity::Medium);
    let status = rule.status.as_ref().map(status_to_string);
    let source = clone_source(source_template, pack, version, path);
    set.report.loaded += 1;
    set.rules.push(LoadedRule {
        uid,
        title: rule.title.clone(),
        id: rule.id.clone(),
        author: rule.author.clone(),
        severity,
        status,
        tags: rule.tags.clone(),
        yaml: yaml.to_string(),
        source,
        unmapped,
        body: RuleBody::Detection(rule.clone()),
    });
}

fn push_correlation(
    set: &mut RuleSet,
    corr: &CorrelationRule,
    yaml: &str,
    path: &Path,
    pack: &str,
    version: &str,
    source_template: &RuleSource,
) {
    set.report.total_rules += 1;
    let id = corr
        .id
        .clone()
        .unwrap_or_else(|| format!("corr-{}", blake3::hash(corr.title.as_bytes()).to_hex()));
    let uid = format!("{pack}:{id}");
    let severity = corr
        .level
        .as_ref()
        .map(level_to_severity)
        .unwrap_or(Severity::Medium);
    let status = corr.status.as_ref().map(status_to_string);
    let source = clone_source(source_template, pack, version, path);
    set.report.loaded += 1;
    set.rules.push(LoadedRule {
        uid,
        title: corr.title.clone(),
        id: corr.id.clone(),
        author: corr.author.clone(),
        severity,
        status,
        tags: corr.tags.clone(),
        yaml: yaml.to_string(),
        source,
        unmapped: false,
        body: RuleBody::Correlation(corr.clone()),
    });
}

fn clone_source(
    source_template: &RuleSource,
    pack: &str,
    version: &str,
    path: &Path,
) -> RuleSource {
    match source_template {
        RuleSource::Builtin => RuleSource::Builtin,
        RuleSource::Sigma { url, .. } => RuleSource::Sigma {
            pack: pack.to_string(),
            version: version.to_string(),
            path: path.display().to_string(),
            url: url.clone(),
        },
    }
}

fn is_windows_rule(rule: &SigmaRule) -> bool {
    if let Some(product) = rule.logsource.product.as_deref() {
        return product.eq_ignore_ascii_case("windows");
    }
    // No product: keep if it has a Windows-ish service/category, or neither (builtins).
    true
}

fn is_unmapped(rule: &SigmaRule, mapping: &LogsourceMapping) -> bool {
    if let Some(cat) = rule.logsource.category.as_deref() {
        if !mapping.is_category_mapped(cat) {
            return true;
        }
    }
    if let Some(svc) = rule.logsource.service.as_deref() {
        if !mapping.is_service_mapped(svc) && rule.logsource.category.is_none() {
            return true;
        }
    }
    false
}

fn level_to_severity(level: &Level) -> Severity {
    match level {
        Level::Informational => Severity::Informational,
        Level::Low => Severity::Low,
        Level::Medium => Severity::Medium,
        Level::High => Severity::High,
        Level::Critical => Severity::Critical,
    }
}

fn status_to_string(s: &Status) -> String {
    match s {
        Status::Stable => "stable".into(),
        Status::Test => "test".into(),
        Status::Experimental => "experimental".into(),
        Status::Deprecated => "deprecated".into(),
        Status::Unsupported => "unsupported".into(),
    }
}

/// Locate builtin rules directory (bundled resources or workspace).
pub fn find_builtins_dir() -> Option<PathBuf> {
    if let Some(root) = lw_core::resource_root() {
        let p = root.join("builtin-rules");
        if p.is_dir() {
            return Some(p);
        }
    }
    None
}

pub fn find_mapping_path() -> Option<PathBuf> {
    lw_core::resource_file("mappings/logsource-windows.yml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::load_logsource_mapping;

    #[test]
    fn loads_builtins() {
        let mapping =
            load_logsource_mapping(find_mapping_path().expect("mapping path")).expect("mapping");
        let dir = find_builtins_dir().expect("builtins dir");
        let set = load_builtins(dir, &mapping).expect("load");
        assert!(set.report.loaded >= 27, "loaded={}", set.report.loaded);
        assert!(
            set.rules.iter().any(|r| r.id.as_deref() == Some("B001")),
            "missing B001"
        );
        assert!(
            set.rules.iter().any(|r| r.id.as_deref() == Some("B010")),
            "missing B010 correlation"
        );
    }
}
