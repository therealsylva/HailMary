use crate::util::read_limited;
use crate::{Error, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTarget {
    pub path: PathBuf,
    pub mode: Option<u32>,
    pub validator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandProfile {
    pub program: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_command_timeout")]
    pub timeout_seconds: u64,
}

fn default_command_timeout() -> u64 {
    300
}

fn default_max_read_bytes() -> u64 {
    8 * 1024 * 1024
}

fn default_max_artifact_bytes() -> usize {
    32 * 1024 * 1024
}

fn default_max_output_bytes() -> usize {
    1024 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicy {
    pub version: u32,
    #[serde(default)]
    pub allowed_actions: BTreeSet<String>,
    #[serde(default)]
    pub allowed_services: BTreeSet<String>,
    #[serde(default)]
    pub log_sources: BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub integrity_roots: BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub file_targets: BTreeMap<String, FileTarget>,
    #[serde(default)]
    pub backup_sources: BTreeMap<String, PathBuf>,
    pub backup_directory: Option<PathBuf>,
    pub staging_directory: Option<PathBuf>,
    #[serde(default)]
    pub command_profiles: BTreeMap<String, CommandProfile>,
    #[serde(default)]
    pub installer_profiles: BTreeMap<String, CommandProfile>,
    #[serde(default)]
    pub patch_profiles: BTreeMap<String, CommandProfile>,
    pub reboot_profile: Option<CommandProfile>,
    #[serde(default)]
    pub redaction_patterns: Vec<String>,
    #[serde(default = "default_max_read_bytes")]
    pub max_read_bytes: u64,
    #[serde(default = "default_max_artifact_bytes")]
    pub max_artifact_bytes: usize,
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: usize,
}

impl AgentPolicy {
    pub fn read(path: &Path) -> Result<Self> {
        let contents = read_limited(path, 4 * 1024 * 1024)?;
        let mut policy: Self = toml::from_str(
            std::str::from_utf8(&contents)
                .map_err(|_| Error::InvalidInput("policy is not valid UTF-8".into()))?,
        )?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        for path in policy
            .log_sources
            .values_mut()
            .chain(policy.integrity_roots.values_mut())
            .chain(policy.backup_sources.values_mut())
        {
            resolve(path, base);
        }
        for target in policy.file_targets.values_mut() {
            resolve(&mut target.path, base);
        }
        if let Some(path) = &mut policy.backup_directory {
            resolve(path, base);
        }
        if let Some(path) = &mut policy.staging_directory {
            resolve(path, base);
        }
        for profile in policy
            .command_profiles
            .values_mut()
            .chain(policy.installer_profiles.values_mut())
            .chain(policy.patch_profiles.values_mut())
        {
            resolve(&mut profile.program, base);
        }
        if let Some(profile) = &mut policy.reboot_profile {
            resolve(&mut profile.program, base);
        }
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::InvalidInput("unsupported policy version".into()));
        }
        if self.max_read_bytes == 0 || self.max_artifact_bytes == 0 || self.max_output_bytes == 0 {
            return Err(Error::InvalidInput(
                "policy byte limits must be greater than zero".into(),
            ));
        }
        for pattern in &self.redaction_patterns {
            Regex::new(pattern).map_err(|error| {
                Error::InvalidInput(format!("invalid redaction regex: {error}"))
            })?;
        }
        for (name, profile) in self
            .command_profiles
            .iter()
            .chain(self.installer_profiles.iter())
            .chain(self.patch_profiles.iter())
        {
            validate_profile(name, profile)?;
        }
        if let Some(profile) = &self.reboot_profile {
            validate_profile("reboot", profile)?;
        }
        Ok(())
    }

    pub fn ensure_action(&self, action: &str) -> Result<()> {
        if self.allowed_actions.contains(action) {
            Ok(())
        } else {
            Err(Error::PolicyDenied(format!(
                "action {action} is not enabled on this node"
            )))
        }
    }

    pub fn redactors(&self) -> Result<Vec<Regex>> {
        self.redaction_patterns
            .iter()
            .map(|pattern| {
                Regex::new(pattern).map_err(|error| Error::InvalidInput(error.to_string()))
            })
            .collect()
    }
}

fn resolve(path: &mut PathBuf, base: &Path) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}

fn validate_profile(name: &str, profile: &CommandProfile) -> Result<()> {
    if !profile.program.is_absolute() || profile.timeout_seconds == 0 {
        return Err(Error::InvalidInput(format!(
            "command profile {name} needs an absolute program path and positive timeout"
        )));
    }
    Ok(())
}
