use lw_core::Result;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// SHA-256 hex digest of a file (read-only).
pub fn sha256_file(path: impl AsRef<Path>) -> Result<String> {
    let mut f = File::open(path.as_ref())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 64];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}
