use crate::model::RiskLevel;
use crate::util::{DEFAULT_MAX_FRAME_BYTES, read_limited, validate_identifier};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConfig {
    #[serde(default = "one")]
    pub read_only: usize,
    #[serde(default = "one")]
    pub reversible: usize,
    #[serde(default = "two")]
    pub disruptive: usize,
    #[serde(default = "two")]
    pub critical: usize,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            read_only: 1,
            reversible: 1,
            disruptive: 2,
            critical: 2,
        }
    }
}

impl ApprovalConfig {
    pub fn required(&self, risk: RiskLevel) -> usize {
        match risk {
            RiskLevel::ReadOnly => self.read_only,
            RiskLevel::Reversible => self.reversible,
            RiskLevel::Disruptive => self.disruptive,
            RiskLevel::Critical => self.critical,
        }
    }
}

fn one() -> usize {
    1
}

fn two() -> usize {
    2
}

fn default_lease_seconds() -> u64 {
    300
}

fn default_poll_seconds() -> u64 {
    15
}

fn default_max_frame_bytes() -> usize {
    DEFAULT_MAX_FRAME_BYTES
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerNetworkConfig {
    pub bind: String,
    pub tls_certificate: PathBuf,
    pub tls_private_key: PathBuf,
    pub client_ca: PathBuf,
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
    #[serde(default = "default_lease_seconds")]
    pub lease_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAuthorization {
    pub certificate_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerConfig {
    pub version: u32,
    pub identity_directory: PathBuf,
    pub identity_password_file: PathBuf,
    pub trust_store: PathBuf,
    pub database: PathBuf,
    pub outbox: PathBuf,
    pub network: ControllerNetworkConfig,
    #[serde(default)]
    pub approvals: ApprovalConfig,
    #[serde(default)]
    pub nodes: BTreeMap<String, NodeAuthorization>,
}

impl ControllerConfig {
    pub fn read(path: &Path) -> Result<Self> {
        let mut config: Self = decode_toml(path)?;
        if config.version != 1 {
            return Err(Error::InvalidInput(
                "unsupported controller configuration version".into(),
            ));
        }
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        resolve(&mut config.identity_directory, base);
        resolve(&mut config.identity_password_file, base);
        resolve(&mut config.trust_store, base);
        resolve(&mut config.database, base);
        resolve(&mut config.outbox, base);
        resolve(&mut config.network.tls_certificate, base);
        resolve(&mut config.network.tls_private_key, base);
        resolve(&mut config.network.client_ca, base);
        if config.network.max_frame_bytes < 1024 || config.network.lease_seconds == 0 {
            return Err(Error::InvalidInput(
                "network limits must be positive and max_frame_bytes at least 1024".into(),
            ));
        }
        for (node_id, authorization) in &config.nodes {
            validate_identifier(node_id, "node ID")?;
            let fingerprint = authorization
                .certificate_sha256
                .strip_prefix("sha256:")
                .unwrap_or(&authorization.certificate_sha256);
            if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(Error::InvalidInput(format!(
                    "node {node_id} has an invalid certificate fingerprint"
                )));
            }
        }
        for count in [
            config.approvals.read_only,
            config.approvals.reversible,
            config.approvals.disruptive,
            config.approvals.critical,
        ] {
            if count == 0 || count > 16 {
                return Err(Error::InvalidInput(
                    "approval counts must be between 1 and 16".into(),
                ));
            }
        }
        Ok(config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentControllerConfig {
    pub address: String,
    pub server_name: String,
    pub ca_certificate: PathBuf,
    pub client_certificate: PathBuf,
    pub client_private_key: PathBuf,
    #[serde(default = "default_poll_seconds")]
    pub poll_seconds: u64,
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub version: u32,
    pub node_id: String,
    pub policy: PathBuf,
    pub state_database: PathBuf,
    pub controller: AgentControllerConfig,
}

impl AgentConfig {
    pub fn read(path: &Path) -> Result<Self> {
        let mut config: Self = decode_toml(path)?;
        if config.version != 1 {
            return Err(Error::InvalidInput(
                "unsupported agent configuration version".into(),
            ));
        }
        validate_identifier(&config.node_id, "node ID")?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        resolve(&mut config.policy, base);
        resolve(&mut config.state_database, base);
        resolve(&mut config.controller.ca_certificate, base);
        resolve(&mut config.controller.client_certificate, base);
        resolve(&mut config.controller.client_private_key, base);
        if config.controller.poll_seconds == 0 || config.controller.max_frame_bytes < 1024 {
            return Err(Error::InvalidInput("invalid agent network limits".into()));
        }
        Ok(config)
    }
}

fn decode_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = read_limited(path, 4 * 1024 * 1024)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::InvalidInput("configuration is not valid UTF-8".into()))?;
    Ok(toml::from_str(text)?)
}

fn resolve(path: &mut PathBuf, base: &Path) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}
