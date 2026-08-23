use crate::util::{sha256_hex, validate_identifier};
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    ReadOnly,
    Reversible,
    Disruptive,
    Critical,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Reversible => "reversible",
            Self::Disruptive => "disruptive",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub media_type: String,
    pub sha256: String,
    pub data: String,
}

impl Attachment {
    pub fn new(name: String, media_type: String, bytes: &[u8]) -> Self {
        use base64::Engine;
        Self {
            name,
            media_type,
            sha256: sha256_hex(bytes),
            data: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    }

    pub fn decode(&self, max_bytes: usize) -> Result<Vec<u8>> {
        use base64::Engine;
        validate_identifier(&self.name, "attachment name")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.data)
            .map_err(|_| {
                Error::InvalidInput(format!("attachment {} has invalid base64", self.name))
            })?;
        if bytes.len() > max_bytes {
            return Err(Error::InvalidInput(format!(
                "attachment {} exceeds the size limit",
                self.name
            )));
        }
        if sha256_hex(&bytes) != self.sha256 {
            return Err(Error::Crypto(format!(
                "attachment {} digest mismatch",
                self.name
            )));
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub job_id: String,
    pub action: String,
    pub targets: Vec<String>,
    #[serde(default)]
    pub params: Map<String, Value>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    #[serde(default)]
    pub dry_run: bool,
    pub created_at: DateTime<Utc>,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

impl Job {
    pub fn validate(&self, max_attachment_bytes: usize) -> Result<()> {
        validate_identifier(&self.job_id, "job ID")?;
        validate_identifier(&self.action, "action")?;
        if self.targets.is_empty() || self.targets.len() > 10_000 {
            return Err(Error::InvalidInput(
                "a job must target between 1 and 10,000 nodes".into(),
            ));
        }
        let mut targets = BTreeSet::new();
        for target in &self.targets {
            validate_identifier(target, "target")?;
            if !targets.insert(target) {
                return Err(Error::InvalidInput(format!("duplicate target {target}")));
            }
        }
        if self.expires_at <= self.created_at {
            return Err(Error::InvalidInput(
                "job expiry must be after creation".into(),
            ));
        }
        if let Some(not_before) = self.not_before
            && not_before >= self.expires_at
        {
            return Err(Error::InvalidInput("not-before must precede expiry".into()));
        }
        let mut names = BTreeSet::new();
        for attachment in &self.attachments {
            if !names.insert(&attachment.name) {
                return Err(Error::InvalidInput(format!(
                    "duplicate attachment {}",
                    attachment.name
                )));
            }
            attachment.decode(max_attachment_bytes)?;
        }
        Ok(())
    }

    pub fn attachment(&self, name: &str, max_bytes: usize) -> Result<Vec<u8>> {
        self.attachments
            .iter()
            .find(|attachment| attachment.name == name)
            .ok_or_else(|| Error::NotFound(format!("attachment {name}")))?
            .decode(max_bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Succeeded,
    Failed,
    Rejected,
    Uncertain,
}

impl ExecutionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
            Self::Uncertain => "uncertain",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeResult {
    pub job_id: String,
    pub node_id: String,
    pub action: String,
    pub status: ExecutionStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub summary: String,
    #[serde(default)]
    pub output: Value,
    #[serde(default)]
    pub artifacts: Vec<Attachment>,
    #[serde(default)]
    pub rollback_performed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaryResult {
    pub job_id: String,
    pub action: String,
    pub status: ExecutionStatus,
    pub exported_at: DateTime<Utc>,
    pub results: Vec<NodeResult>,
}
