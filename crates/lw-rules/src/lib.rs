#![deny(unsafe_code)]

//! Sigma rule pack loading, profiles, and Windows logsource mapping.

mod download;
mod load;
mod mapping;
mod pack;
mod profile;

pub use download::{download_sigma_pack, SigmaPackKind, SIGMA_DRL_NOTICE};
pub use load::{
    find_builtins_dir, find_mapping_path, load_builtins, load_rules_from_dir, load_rules_from_zip,
    LoadReport, LoadedRule, RuleBody, RuleSet,
};
pub use mapping::{load_logsource_mapping, LogsourceMapping};
pub use pack::{
    hash_dir, import_pack_dir, import_pack_zip, list_packs, pack_install_dir, packs_dir,
    read_manifest, write_manifest, RulePackManifest,
};
pub use profile::{filter_rules, RuleProfile};

pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}
