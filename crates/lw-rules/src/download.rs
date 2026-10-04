use crate::load::{load_rules_from_dir, RuleSet};
use crate::mapping::LogsourceMapping;
use crate::pack::{hash_dir, pack_install_dir, packs_dir, write_manifest, RulePackManifest};
use lw_core::{Error, Result, RuleSource};
use std::fs;
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigmaPackKind {
    Core,
    CorePlus,
    CorePlusPlus,
    EmergingThreats,
    All,
}

impl SigmaPackKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "core" | "sigma_core" => Some(Self::Core),
            "core+" | "core_plus" | "sigma_core+" => Some(Self::CorePlus),
            "core++" | "core_plusplus" | "sigma_core++" => Some(Self::CorePlusPlus),
            "et" | "emerging" | "emerging_threats" | "sigma_emerging_threats_addon" => {
                Some(Self::EmergingThreats)
            }
            "all" | "sigma_all_rules" => Some(Self::All),
            _ => None,
        }
    }

    pub fn asset_prefix(self) -> &'static str {
        match self {
            Self::Core => "sigma_core.zip",
            Self::CorePlus => "sigma_core+.zip",
            Self::CorePlusPlus => "sigma_core++.zip",
            Self::EmergingThreats => "sigma_emerging_threats_addon.zip",
            Self::All => "sigma_all_rules.zip",
        }
    }

    pub fn pack_id(self) -> &'static str {
        match self {
            Self::Core => "sigma_core",
            Self::CorePlus => "sigma_core_plus",
            Self::CorePlusPlus => "sigma_core_plusplus",
            Self::EmergingThreats => "sigma_emerging_threats",
            Self::All => "sigma_all_rules",
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct GhRelease {
    tag_name: String,
    assets: Vec<GhAsset>,
}

#[derive(Debug, serde::Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

/// Download a SigmaHQ release asset into the packs directory.
///
/// Network use is opt-in (caller invokes this explicitly).
pub fn download_sigma_pack(
    kind: SigmaPackKind,
    mapping: &LogsourceMapping,
    dest_root: Option<&Path>,
) -> Result<(RulePackManifest, RuleSet)> {
    let (tag, url) = resolve_latest_asset(kind)?;
    let root = dest_root.map(Path::to_path_buf).unwrap_or_else(packs_dir);
    let dest = pack_install_dir(&root, kind.pack_id(), &tag);
    fs::create_dir_all(&dest)?;

    let zip_path = dest.join(kind.asset_prefix());
    download_file(&url, &zip_path)?;
    extract_zip_yaml(&zip_path, &dest)?;

    let source = RuleSource::Sigma {
        pack: kind.pack_id().to_string(),
        version: tag.clone(),
        path: dest.display().to_string(),
        url: Some(url.clone()),
    };
    let set = load_rules_from_dir(&dest, kind.pack_id(), &tag, source, mapping)?;
    let hash = hash_dir(&dest)?;
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
    let manifest = RulePackManifest {
        id: kind.pack_id().to_string(),
        version: tag,
        kind: kind.asset_prefix().to_string(),
        source_url: Some(url),
        downloaded_at: now,
        blake3: hash,
        rule_count: set.report.loaded,
        file_count: set.report.total_files,
        path: dest.display().to_string(),
    };
    write_manifest(&dest, &manifest)?;
    Ok((manifest, set))
}

fn resolve_latest_asset(kind: SigmaPackKind) -> Result<(String, String)> {
    let api = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest";
    let mut resp = ureq::get(api)
        .header("User-Agent", "logwarden/0.1")
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| Error::msg(format!("github releases API: {e}")))?;
    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| Error::msg(format!("github body: {e}")))?;
    let release: GhRelease =
        serde_json::from_str(&body).map_err(|e| Error::msg(format!("github json: {e}")))?;
    let want = kind.asset_prefix();
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == want || a.name.starts_with(&want.replace(".zip", "")))
        .or_else(|| release.assets.iter().find(|a| a.name.contains(want)))
        .ok_or_else(|| {
            Error::msg(format!(
                "asset {want} not found in SigmaHQ release {}",
                release.tag_name
            ))
        })?;
    Ok((release.tag_name, asset.browser_download_url.clone()))
}

fn download_file(url: &str, dest: &Path) -> Result<()> {
    let mut resp = ureq::get(url)
        .header("User-Agent", "logwarden/0.1")
        .call()
        .map_err(|e| Error::msg(format!("download {url}: {e}")))?;
    let mut reader = resp.body_mut().as_reader();
    let mut file = fs::File::create(dest)?;
    std::io::copy(&mut reader, &mut file)?;
    Ok(())
}

fn extract_zip_yaml(zip_path: &Path, dest: &Path) -> Result<()> {
    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| Error::msg(format!("zip: {e}")))?;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| Error::msg(format!("zip entry: {e}")))?;
        let name = entry.name().to_string();
        if entry.is_dir() {
            continue;
        }
        if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }
        let rel = PathBuf::from(&name);
        if rel
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            continue;
        }
        let out_path = dest.join(&rel);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = fs::File::create(&out_path)?;
        std::io::copy(&mut entry, &mut out)?;
    }
    Ok(())
}

/// License notice shown before/after SigmaHQ pack download (DRL 1.1).
pub const SIGMA_DRL_NOTICE: &str = "\
Sigma rule packs are licensed under the Detection Rule License (DRL) 1.1. \
Author attribution is required on every match. See https://github.com/SigmaHQ/sigma.";
