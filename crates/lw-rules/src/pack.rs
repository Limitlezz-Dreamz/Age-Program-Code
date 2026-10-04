use crate::load::{load_rules_from_dir, load_rules_from_zip, RuleSet};
use crate::mapping::LogsourceMapping;
use lw_core::{Error, Result, RuleSource};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePackManifest {
    pub id: String,
    pub version: String,
    pub kind: String,
    pub source_url: Option<String>,
    pub downloaded_at: String,
    pub blake3: String,
    pub rule_count: u64,
    pub file_count: u64,
    pub path: String,
}

/// App data rules root: `$XDG_DATA_HOME/logwarden/rules` or `./data/logwarden/rules`.
pub fn packs_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("logwarden").join("rules");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("logwarden")
            .join("rules");
    }
    PathBuf::from("data").join("logwarden").join("rules")
}

pub fn pack_install_dir(root: &Path, pack_id: &str, version: &str) -> PathBuf {
    root.join(pack_id).join(version)
}

pub fn write_manifest(dir: &Path, manifest: &RulePackManifest) -> Result<()> {
    fs::create_dir_all(dir)?;
    let p = dir.join("manifest.json");
    fs::write(p, serde_json::to_string_pretty(manifest)?)?;
    Ok(())
}

pub fn read_manifest(dir: &Path) -> Result<RulePackManifest> {
    let text = fs::read_to_string(dir.join("manifest.json"))?;
    serde_json::from_str(&text).map_err(|e| Error::msg(e.to_string()))
}

pub fn list_packs(root: impl AsRef<Path>) -> Result<Vec<RulePackManifest>> {
    let root = root.as_ref();
    let mut out = Vec::new();
    if !root.is_dir() {
        return Ok(out);
    }
    for pack_entry in fs::read_dir(root)? {
        let pack_entry = pack_entry?;
        if !pack_entry.file_type()?.is_dir() {
            continue;
        }
        for ver_entry in fs::read_dir(pack_entry.path())? {
            let ver_entry = ver_entry?;
            if !ver_entry.file_type()?.is_dir() {
                continue;
            }
            let manifest_path = ver_entry.path().join("manifest.json");
            if manifest_path.is_file() {
                match read_manifest(&ver_entry.path()) {
                    Ok(m) => out.push(m),
                    Err(e) => tracing::warn!("skip pack {}: {e}", ver_entry.path().display()),
                }
            }
        }
    }
    out.sort_by(|a, b| (&a.id, &a.version).cmp(&(&b.id, &b.version)));
    Ok(out)
}

/// Import a local folder of Sigma YAML into the packs directory.
pub fn import_pack_dir(
    src: impl AsRef<Path>,
    pack_id: &str,
    version: &str,
    mapping: &LogsourceMapping,
    dest_root: Option<&Path>,
) -> Result<(RulePackManifest, RuleSet)> {
    let src = src.as_ref();
    let root = dest_root.map(Path::to_path_buf).unwrap_or_else(packs_dir);
    let dest = pack_install_dir(&root, pack_id, version);
    fs::create_dir_all(&dest)?;
    copy_dir_yaml(src, &dest)?;

    let source = RuleSource::Sigma {
        pack: pack_id.to_string(),
        version: version.to_string(),
        path: dest.display().to_string(),
        url: None,
    };
    let set = load_rules_from_dir(&dest, pack_id, version, source, mapping)?;
    let hash = hash_dir(&dest)?;
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
    let manifest = RulePackManifest {
        id: pack_id.to_string(),
        version: version.to_string(),
        kind: "local-dir".into(),
        source_url: None,
        downloaded_at: now,
        blake3: hash,
        rule_count: set.report.loaded,
        file_count: set.report.total_files,
        path: dest.display().to_string(),
    };
    write_manifest(&dest, &manifest)?;
    Ok((manifest, set))
}

/// Import a local zip of Sigma YAML into the packs directory.
pub fn import_pack_zip(
    zip_path: impl AsRef<Path>,
    pack_id: &str,
    version: &str,
    mapping: &LogsourceMapping,
    dest_root: Option<&Path>,
) -> Result<(RulePackManifest, RuleSet)> {
    let zip_path = zip_path.as_ref();
    let root = dest_root.map(Path::to_path_buf).unwrap_or_else(packs_dir);
    let dest = pack_install_dir(&root, pack_id, version);
    fs::create_dir_all(&dest)?;

    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| Error::msg(format!("zip: {e}")))?;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| Error::msg(format!("zip entry: {e}")))?;
        let name = entry.name().to_string();
        if entry.is_dir() || !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }
        // Flatten zip paths into dest, preserving relative structure safely.
        let rel = Path::new(&name);
        if rel
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            continue;
        }
        let out_path = dest.join(rel);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = fs::File::create(&out_path)?;
        std::io::copy(&mut entry, &mut out)?;
    }

    let set = load_rules_from_zip(zip_path, pack_id, version, None, mapping)?;
    // Prefer loading from extracted dest so path in source matches install.
    let source = RuleSource::Sigma {
        pack: pack_id.to_string(),
        version: version.to_string(),
        path: dest.display().to_string(),
        url: None,
    };
    let set = if set.report.loaded > 0 {
        load_rules_from_dir(&dest, pack_id, version, source, mapping)?
    } else {
        set
    };

    let hash = hash_dir(&dest)?;
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
    let manifest = RulePackManifest {
        id: pack_id.to_string(),
        version: version.to_string(),
        kind: "local-zip".into(),
        source_url: None,
        downloaded_at: now,
        blake3: hash,
        rule_count: set.report.loaded,
        file_count: set.report.total_files,
        path: dest.display().to_string(),
    };
    write_manifest(&dest, &manifest)?;
    Ok((manifest, set))
}

fn copy_dir_yaml(src: &Path, dest: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(src)
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
        let rel = path.strip_prefix(src).unwrap_or(path);
        let out = dest.join(rel);
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(path, &out)?;
    }
    Ok(())
}

pub fn hash_dir(dir: &Path) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut paths: Vec<PathBuf> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter(|e| {
            e.path()
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n != "manifest.json")
                .unwrap_or(true)
        })
        .map(|e| e.path().to_path_buf())
        .collect();
    paths.sort();
    for p in paths {
        let rel = p.strip_prefix(dir).unwrap_or(&p);
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(&[0]);
        hasher.update(&fs::read(&p)?);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::find_builtins_dir;
    use crate::load::find_mapping_path;
    use crate::mapping::load_logsource_mapping;

    #[test]
    fn import_builtins_as_local_pack() {
        let mapping = load_logsource_mapping(find_mapping_path().unwrap()).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let (manifest, set) = import_pack_dir(
            find_builtins_dir().unwrap(),
            "test-builtins",
            "0.1.0",
            &mapping,
            Some(tmp.path()),
        )
        .unwrap();
        assert!(manifest.rule_count >= 27);
        assert_eq!(set.report.loaded, manifest.rule_count);
        assert!(tmp
            .path()
            .join("test-builtins/0.1.0/manifest.json")
            .is_file());
    }
}
