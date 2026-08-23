use crate::{Error, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub const DEFAULT_MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|error| Error::InvalidInput(error.to_string()))
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}

pub fn now() -> DateTime<Utc> {
    Utc::now()
}

pub fn validate_identifier(value: &str, field: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "{field} must contain only letters, digits, '.', '_', ':' or '-'"
        )))
    }
}

pub fn validate_relative_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(Error::UnsafePath(path.to_path_buf()));
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(Error::UnsafePath(path.to_path_buf()));
        }
    }
    Ok(())
}

pub fn confined_path(root: &Path, relative: &Path) -> Result<PathBuf> {
    validate_relative_path(relative)?;
    let canonical_root = root.canonicalize()?;
    let candidate = canonical_root.join(relative);
    if candidate.exists() {
        let canonical_candidate = candidate.canonicalize()?;
        if !canonical_candidate.starts_with(&canonical_root) {
            return Err(Error::UnsafePath(candidate));
        }
        Ok(canonical_candidate)
    } else {
        let parent = candidate
            .parent()
            .ok_or_else(|| Error::UnsafePath(candidate.clone()))?
            .canonicalize()?;
        if !parent.starts_with(&canonical_root) {
            return Err(Error::UnsafePath(candidate));
        }
        Ok(candidate)
    }
}

pub fn read_limited(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(Error::UnsafePath(path.to_path_buf()));
    }
    if metadata.len() > max_bytes {
        return Err(Error::InvalidInput(format!(
            "{} exceeds the {} byte limit",
            path.display(),
            max_bytes
        )));
    }
    Ok(fs::read(path)?)
}

pub fn atomic_write(path: &Path, contents: &[u8], private: bool) -> Result<()> {
    #[cfg(not(unix))]
    let _ = private;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(contents)?;
    temporary.as_file_mut().sync_all()?;

    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    temporary
        .persist(path)
        .map_err(|error| Error::Io(error.error))?;

    #[cfg(unix)]
    {
        let directory = OpenOptions::new().read(true).open(parent)?;
        directory.sync_all()?;
    }
    Ok(())
}

pub fn parse_duration_seconds(value: &str) -> Result<u64> {
    let (number, multiplier) = match value.chars().last() {
        Some('s') => (&value[..value.len() - 1], 1),
        Some('m') => (&value[..value.len() - 1], 60),
        Some('h') => (&value[..value.len() - 1], 60 * 60),
        Some('d') => (&value[..value.len() - 1], 24 * 60 * 60),
        Some(last) if last.is_ascii_digit() => (value, 1),
        _ => return Err(Error::InvalidInput("invalid duration".into())),
    };
    number
        .parse::<u64>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
        .ok_or_else(|| Error::InvalidInput("invalid duration".into()))
}
