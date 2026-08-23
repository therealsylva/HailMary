use crate::crypto::{parse_verifying_key, verify};
use crate::identity::PublicIdentity;
use crate::model::RiskLevel;
use crate::util::{atomic_write, canonical_json, now, read_limited};
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

const TRUST_FORMAT: &str = "hailmary.trust-store";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum TrustRole {
    Operator,
    Controller,
    Agent,
    Auditor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustEntry {
    pub identity: PublicIdentity,
    pub role: TrustRole,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    pub max_risk: RiskLevel,
    #[serde(default)]
    pub revoked: bool,
    pub added_at: DateTime<Utc>,
}

impl TrustEntry {
    pub fn allows(&self, action: &str, risk: RiskLevel) -> bool {
        !self.revoked
            && risk <= self.max_risk
            && (self.allowed_actions.iter().any(|item| item == "*")
                || self.allowed_actions.iter().any(|item| item == action))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustStore {
    pub format: String,
    pub version: u32,
    pub trust_epoch: u64,
    pub entries: BTreeMap<String, TrustEntry>,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self {
            format: TRUST_FORMAT.into(),
            version: 1,
            trust_epoch: 1,
            entries: BTreeMap::new(),
        }
    }
}

impl TrustStore {
    pub fn read(path: &Path) -> Result<Self> {
        let store: Self = serde_json::from_slice(&read_limited(path, 16 * 1024 * 1024)?)?;
        if store.format != TRUST_FORMAT || store.version != 1 {
            return Err(Error::InvalidInput("unsupported trust-store format".into()));
        }
        for (key_id, entry) in &store.entries {
            entry.identity.validate()?;
            if key_id != &entry.identity.signing.key_id {
                return Err(Error::Crypto("trust-store key ID mismatch".into()));
            }
        }
        Ok(store)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        atomic_write(path, &canonical_json(self)?, true)
    }

    pub fn add(
        &mut self,
        identity: PublicIdentity,
        role: TrustRole,
        allowed_actions: Vec<String>,
        max_risk: RiskLevel,
    ) -> Result<()> {
        identity.validate()?;
        let key_id = identity.signing.key_id.clone();
        if self.entries.contains_key(&key_id) {
            return Err(Error::InvalidInput(format!(
                "signing key {key_id} is already trusted"
            )));
        }
        self.entries.insert(
            key_id,
            TrustEntry {
                identity,
                role,
                allowed_actions,
                max_risk,
                revoked: false,
                added_at: now(),
            },
        );
        self.trust_epoch = self.trust_epoch.saturating_add(1);
        Ok(())
    }

    pub fn revoke(&mut self, key_id: &str) -> Result<()> {
        let entry = self
            .entries
            .get_mut(key_id)
            .ok_or_else(|| Error::NotFound(format!("trusted key {key_id}")))?;
        entry.revoked = true;
        self.trust_epoch = self.trust_epoch.saturating_add(1);
        Ok(())
    }

    pub fn entry(&self, key_id: &str) -> Option<&TrustEntry> {
        self.entries.get(key_id).filter(|entry| !entry.revoked)
    }

    pub fn find_identity(&self, identity_id: &str) -> Option<&TrustEntry> {
        self.entries
            .values()
            .find(|entry| !entry.revoked && entry.identity.identity_id == identity_id)
    }

    pub fn verify_signature(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<&TrustEntry> {
        let entry = self
            .entry(key_id)
            .ok_or_else(|| Error::Authentication(format!("untrusted signing key {key_id}")))?;
        let key = parse_verifying_key(&entry.identity.signing.der()?)?;
        verify(&key, message, signature)?;
        Ok(entry)
    }
}
