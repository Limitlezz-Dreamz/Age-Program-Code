use lw_core::{DiscoveredFile, Result, TsMicros, EVTX_MAGIC};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Recursively discover EVTX files under the given paths.
pub fn discover_evtx_paths(paths: &[PathBuf]) -> Result<Vec<DiscoveredFile>> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_file() {
            if is_evtx_file(p)? {
                out.push(discovered(p)?);
            }
            continue;
        }
        if p.is_dir() {
            for entry in WalkDir::new(p)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if path.is_file() && is_evtx_file(path)? {
                    out.push(discovered(path)?);
                }
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    Ok(out)
}

/// True if the path looks like EVTX: `.evtx` extension **or** `ElfFile\0` magic.
pub fn is_evtx_file(path: &Path) -> Result<bool> {
    if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
    {
        // Still accept .evtx even if truncated/empty — parser will record errors.
        return Ok(true);
    }
    has_evtx_magic(path)
}

fn has_evtx_magic(path: &Path) -> Result<bool> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };
    let mut buf = [0u8; 8];
    match f.read_exact(&mut buf) {
        Ok(()) => Ok(&buf == EVTX_MAGIC),
        Err(_) => Ok(false),
    }
}

fn discovered(path: &Path) -> Result<DiscoveredFile> {
    let meta = std::fs::metadata(path)?;
    let mtime = meta.modified().ok().and_then(|t| {
        t.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_micros() as TsMicros)
    });
    Ok(DiscoveredFile {
        path: path.to_path_buf(),
        size: meta.len(),
        mtime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn detects_magic_without_extension() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("renamed.bin");
        let mut f = File::create(&p).unwrap();
        f.write_all(EVTX_MAGIC).unwrap();
        f.write_all(&[0u8; 100]).unwrap();
        assert!(is_evtx_file(&p).unwrap());
    }

    #[test]
    fn rejects_non_evtx() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("notes.txt");
        std::fs::write(&p, b"hello").unwrap();
        assert!(!is_evtx_file(&p).unwrap());
    }
}
