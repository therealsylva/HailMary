use crate::bundle::{Bundle, BundleKind};
use crate::config::ControllerConfig;
use crate::identity::Identity;
use crate::model::{ExecutionStatus, Job, MaryResult, NodeResult};
use crate::task::action_risk;
use crate::trust::{TrustRole, TrustStore};
use crate::util::{canonical_json, now, sha256_hex};
use crate::{Error, Result};
use chrono::Duration;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub struct Controller {
    pub config: ControllerConfig,
    identity: Identity,
    trust: TrustStore,
}

impl Controller {
    pub fn load(config: ControllerConfig, password: &[u8]) -> Result<Self> {
        let identity = Identity::load(&config.identity_directory, password)?;
        let trust = TrustStore::read(&config.trust_store)?;
        initialize_database(&config.database)?;
        fs::create_dir_all(&config.outbox)?;
        Ok(Self {
            config,
            identity,
            trust,
        })
    }

    pub fn initialize(config: &ControllerConfig) -> Result<()> {
        initialize_database(&config.database)?;
        fs::create_dir_all(&config.outbox)?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub fn import_hail(&self, bundle: &Bundle) -> Result<String> {
        bundle.validate_time(now())?;
        if bundle.kind() != BundleKind::Hail {
            return Err(Error::InvalidInput(
                "controller imports only .hail bundles".into(),
            ));
        }
        let signers = bundle.verify_signatures(&self.trust)?;
        let job: Job = bundle.decrypt(&self.identity)?;
        job.validate(32 * 1024 * 1024)?;
        if job.job_id != bundle.protected.job_id
            || job.created_at != bundle.protected.created_at
            || job.not_before != bundle.protected.not_before
            || job.expires_at != bundle.protected.expires_at
        {
            return Err(Error::Crypto(
                "protected bundle metadata does not match the job".into(),
            ));
        }
        let risk = action_risk(&job.action)
            .ok_or_else(|| Error::InvalidInput(format!("unsupported action {}", job.action)))?;
        let sender_signer = signers
            .iter()
            .find(|entry| entry.identity.identity_id == bundle.protected.sender)
            .ok_or_else(|| Error::Authentication("bundle sender signature is missing".into()))?;
        if sender_signer.role != TrustRole::Operator || !sender_signer.allows(&job.action, risk) {
            return Err(Error::PolicyDenied(
                "bundle sender is not authorized to initiate this action".into(),
            ));
        }
        let sender_key_id = sender_signer.identity.signing.key_id.clone();
        let authorized: BTreeSet<&str> = signers
            .iter()
            .filter(|entry| entry.role == TrustRole::Operator && entry.allows(&job.action, risk))
            .map(|entry| entry.identity.identity_id.as_str())
            .collect();
        let required = self.config.approvals.required(risk);
        if authorized.len() < required {
            return Err(Error::PolicyDenied(format!(
                "{} requires {required} authorized signature(s); received {}",
                job.action,
                authorized.len()
            )));
        }
        for target in &job.targets {
            if !self.config.nodes.contains_key(target) {
                return Err(Error::PolicyDenied(format!(
                    "target node {target} is not enrolled"
                )));
            }
        }

        let mut connection = open_database(&self.config.database)?;
        let transaction = connection.transaction()?;
        let last_sequence: Option<u64> = transaction
            .query_row(
                "SELECT last_sequence FROM sender_sequences WHERE sender_id = ?1",
                [&bundle.protected.sender],
                |row| row.get(0),
            )
            .optional()?;
        if last_sequence.is_some_and(|last| bundle.protected.sequence <= last) {
            return Err(Error::Replay {
                sender: bundle.protected.sender.clone(),
                sequence: bundle.protected.sequence,
            });
        }
        let envelope = canonical_json(bundle)?;
        transaction.execute(
            "INSERT INTO jobs
             (job_id, bundle_id, sender_id, sender_key_id, action, risk, state, envelope, imported_at, not_before, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued', ?7, ?8, ?9, ?10)",
            params![
                job.job_id,
                bundle.protected.bundle_id,
                bundle.protected.sender,
                sender_key_id,
                job.action,
                risk.as_str(),
                envelope,
                now().to_rfc3339(),
                job.not_before.map(|value| value.to_rfc3339()),
                job.expires_at.to_rfc3339(),
            ],
        )
        .map_err(|error| {
            if matches!(error, rusqlite::Error::SqliteFailure(ref inner, _) if inner.extended_code == 2067)
            {
                Error::Replay {
                    sender: bundle.protected.sender.clone(),
                    sequence: bundle.protected.sequence,
                }
            } else {
                Error::Database(error)
            }
        })?;
        for target in &job.targets {
            transaction.execute(
                "INSERT INTO job_targets (job_id, node_id, state, attempts, updated_at)
                 VALUES (?1, ?2, 'queued', 0, ?3)",
                params![job.job_id, target, now().to_rfc3339()],
            )?;
        }
        transaction.execute(
            "INSERT INTO sender_sequences (sender_id, last_sequence)
             VALUES (?1, ?2)
             ON CONFLICT(sender_id) DO UPDATE SET last_sequence = excluded.last_sequence",
            params![bundle.protected.sender, bundle.protected.sequence],
        )?;
        append_audit(
            &transaction,
            "hail_imported",
            &bundle.protected.sender,
            Some(&job.job_id),
            &json!({
                "bundle_id": bundle.protected.bundle_id,
                "action": job.action,
                "targets": job.targets,
                "risk": risk,
                "authorized_signers": authorized,
            }),
        )?;
        transaction.commit()?;
        Ok(job.job_id)
    }

    pub fn claim(&self, node_id: &str) -> Result<Option<Job>> {
        self.ensure_node(node_id)?;
        let mut connection = open_database(&self.config.database)?;
        let transaction = connection.transaction()?;
        let timestamp = now();
        transaction.execute(
            "UPDATE job_targets SET state = 'queued', lease_until = NULL, updated_at = ?1
             WHERE state = 'leased' AND lease_until < ?1",
            [timestamp.to_rfc3339()],
        )?;
        let row: Option<(String, Vec<u8>)> = transaction
            .query_row(
                "SELECT j.job_id, j.envelope
                 FROM jobs j JOIN job_targets t ON j.job_id = t.job_id
                 WHERE t.node_id = ?1 AND t.state = 'queued' AND j.state = 'queued'
                   AND (j.not_before IS NULL OR j.not_before <= ?2) AND j.expires_at > ?2
                 ORDER BY j.imported_at ASC LIMIT 1",
                params![node_id, timestamp.to_rfc3339()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((job_id, envelope)) = row else {
            transaction.commit()?;
            return Ok(None);
        };
        let lease_until = timestamp
            + Duration::seconds(
                i64::try_from(self.config.network.lease_seconds).unwrap_or(i64::MAX),
            );
        transaction.execute(
            "UPDATE job_targets SET state = 'leased', attempts = attempts + 1,
             lease_until = ?3, updated_at = ?4 WHERE job_id = ?1 AND node_id = ?2",
            params![
                job_id,
                node_id,
                lease_until.to_rfc3339(),
                timestamp.to_rfc3339()
            ],
        )?;
        append_audit(
            &transaction,
            "job_claimed",
            node_id,
            Some(&job_id),
            &json!({"lease_until": lease_until}),
        )?;
        transaction.commit()?;
        let bundle: Bundle = serde_json::from_slice(&envelope)?;
        let job: Job = bundle.decrypt(&self.identity)?;
        Ok(Some(job))
    }

    pub fn complete(&self, node_id: &str, result: &NodeResult) -> Result<()> {
        self.ensure_node(node_id)?;
        if result.node_id != node_id {
            return Err(Error::Authentication(
                "result node does not match authenticated node".into(),
            ));
        }
        let mut connection = open_database(&self.config.database)?;
        let transaction = connection.transaction()?;
        let job_action: String = transaction
            .query_row(
                "SELECT action FROM jobs WHERE job_id = ?1",
                [&result.job_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("job {}", result.job_id)))?;
        if result.action != job_action {
            return Err(Error::InvalidInput(
                "result action does not match job".into(),
            ));
        }
        let existing: Option<(String, Option<String>)> = transaction
            .query_row(
                "SELECT state, result_json FROM job_targets WHERE job_id = ?1 AND node_id = ?2",
                params![result.job_id, node_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((state, existing_result)) = existing else {
            return Err(Error::PolicyDenied(
                "job was not assigned to this node".into(),
            ));
        };
        let result_json = String::from_utf8(canonical_json(result)?)
            .map_err(|_| Error::Protocol("canonical JSON was not UTF-8".into()))?;
        if state == "completed" {
            return if existing_result.as_deref() == Some(&result_json) {
                Ok(())
            } else {
                Err(Error::Replay {
                    sender: node_id.into(),
                    sequence: 0,
                })
            };
        }
        transaction.execute(
            "UPDATE job_targets SET state = 'completed', result_json = ?3,
             lease_until = NULL, updated_at = ?4 WHERE job_id = ?1 AND node_id = ?2",
            params![result.job_id, node_id, result_json, now().to_rfc3339()],
        )?;
        let outstanding: u64 = transaction.query_row(
            "SELECT COUNT(*) FROM job_targets WHERE job_id = ?1 AND state != 'completed'",
            [&result.job_id],
            |row| row.get(0),
        )?;
        if outstanding == 0 {
            transaction.execute(
                "UPDATE jobs SET state = 'completed' WHERE job_id = ?1",
                [&result.job_id],
            )?;
        }
        append_audit(
            &transaction,
            "job_completed",
            node_id,
            Some(&result.job_id),
            &json!({"status": result.status, "summary": result.summary}),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn export_mary(&self, job_id: &str) -> Result<Bundle> {
        let mut connection = open_database(&self.config.database)?;
        let transaction = connection.transaction()?;
        if let Some(bytes) = transaction
            .query_row(
                "SELECT bundle FROM exports WHERE job_id = ?1",
                [job_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            let bundle = serde_json::from_slice(&bytes)?;
            transaction.commit()?;
            return Ok(bundle);
        }
        let (sender_id, sender_key_id, action, state): (String, String, String, String) =
            transaction
                .query_row(
                    "SELECT sender_id, sender_key_id, action, state FROM jobs WHERE job_id = ?1",
                    [job_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?
                .ok_or_else(|| Error::NotFound(format!("job {job_id}")))?;
        if state != "completed" {
            return Err(Error::InvalidInput(format!("job {job_id} is not complete")));
        }
        let mut statement = transaction.prepare(
            "SELECT result_json FROM job_targets WHERE job_id = ?1 ORDER BY node_id ASC",
        )?;
        let results: Vec<NodeResult> = statement
            .query_map([job_id], |row| row.get::<_, String>(0))?
            .map(|row| {
                row.map_err(Error::Database)
                    .and_then(|value| serde_json::from_str(&value).map_err(Error::Json))
            })
            .collect::<Result<Vec<_>>>()?;
        drop(statement);
        let status = aggregate_status(&results);
        let payload = MaryResult {
            job_id: job_id.into(),
            action,
            status,
            exported_at: now(),
            results,
        };
        let recipient = self
            .trust
            .entry(&sender_key_id)
            .filter(|entry| entry.identity.identity_id == sender_id)
            .ok_or_else(|| {
                Error::Authentication(format!("sender key {sender_key_id} is not trusted"))
            })?
            .identity
            .clone();
        let sequence = next_outbound_sequence(&transaction, &self.identity.public.identity_id)?;
        let bundle = Bundle::seal(
            BundleKind::Mary,
            job_id,
            &self.identity,
            &[recipient],
            &payload,
            sequence,
            now(),
            None,
            now() + Duration::days(30),
        )?;
        transaction.execute(
            "INSERT INTO exports (job_id, bundle, exported_at) VALUES (?1, ?2, ?3)",
            params![job_id, canonical_json(&bundle)?, now().to_rfc3339()],
        )?;
        append_audit(
            &transaction,
            "mary_exported",
            &self.identity.public.identity_id,
            Some(job_id),
            &json!({"bundle_id": bundle.protected.bundle_id, "recipient": sender_id}),
        )?;
        transaction.commit()?;
        Ok(bundle)
    }

    pub fn status(&self, job_id: Option<&str>) -> Result<Value> {
        let connection = open_database(&self.config.database)?;
        if let Some(job_id) = job_id {
            let job: (String, String, String, String, String) = connection
                .query_row(
                    "SELECT job_id, sender_id, action, risk, state FROM jobs WHERE job_id = ?1",
                    [job_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| Error::NotFound(format!("job {job_id}")))?;
            let mut statement = connection.prepare(
                "SELECT node_id, state, attempts, lease_until, updated_at FROM job_targets
                 WHERE job_id = ?1 ORDER BY node_id ASC",
            )?;
            let targets = statement
                .query_map([job_id], |row| {
                    Ok(json!({
                        "node_id": row.get::<_, String>(0)?,
                        "state": row.get::<_, String>(1)?,
                        "attempts": row.get::<_, u64>(2)?,
                        "lease_until": row.get::<_, Option<String>>(3)?,
                        "updated_at": row.get::<_, String>(4)?,
                    }))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(json!({
                "job_id": job.0, "sender": job.1, "action": job.2,
                "risk": job.3, "state": job.4, "targets": targets,
            }))
        } else {
            let mut statement = connection.prepare(
                "SELECT job_id, sender_id, action, risk, state, imported_at
                 FROM jobs ORDER BY imported_at DESC LIMIT 100",
            )?;
            let jobs = statement
                .query_map([], |row| {
                    Ok(json!({
                        "job_id": row.get::<_, String>(0)?,
                        "sender": row.get::<_, String>(1)?,
                        "action": row.get::<_, String>(2)?,
                        "risk": row.get::<_, String>(3)?,
                        "state": row.get::<_, String>(4)?,
                        "imported_at": row.get::<_, String>(5)?,
                    }))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(json!({"jobs": jobs}))
        }
    }

    pub fn verify_audit(&self) -> Result<u64> {
        verify_audit_database(&self.config.database)
    }

    pub fn expected_certificate_fingerprint(&self, node_id: &str) -> Result<String> {
        self.ensure_node(node_id)?;
        Ok(self.config.nodes[node_id]
            .certificate_sha256
            .strip_prefix("sha256:")
            .unwrap_or(&self.config.nodes[node_id].certificate_sha256)
            .to_ascii_lowercase())
    }

    fn ensure_node(&self, node_id: &str) -> Result<()> {
        if self.config.nodes.contains_key(node_id) {
            Ok(())
        } else {
            Err(Error::Authentication(format!("unenrolled node {node_id}")))
        }
    }
}

fn initialize_database(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let connection = open_database(path)?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            bundle_id TEXT NOT NULL UNIQUE,
            sender_id TEXT NOT NULL,
            sender_key_id TEXT NOT NULL,
            action TEXT NOT NULL,
            risk TEXT NOT NULL,
            state TEXT NOT NULL,
            envelope BLOB NOT NULL,
            imported_at TEXT NOT NULL,
            not_before TEXT,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS job_targets (
            job_id TEXT NOT NULL REFERENCES jobs(job_id),
            node_id TEXT NOT NULL,
            state TEXT NOT NULL,
            attempts INTEGER NOT NULL,
            lease_until TEXT,
            result_json TEXT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (job_id, node_id)
        );
        CREATE TABLE IF NOT EXISTS sender_sequences (
            sender_id TEXT PRIMARY KEY,
            last_sequence INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS outbound_sequences (
            sender_id TEXT PRIMARY KEY,
            last_sequence INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS exports (
            job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
            bundle BLOB NOT NULL,
            exported_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at TEXT NOT NULL,
            event TEXT NOT NULL,
            actor TEXT NOT NULL,
            job_id TEXT,
            details_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_targets_claim
            ON job_targets(node_id, state, updated_at);",
    )?;
    Ok(())
}

fn open_database(path: &Path) -> Result<Connection> {
    let connection = Connection::open(path)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(connection)
}

fn append_audit(
    transaction: &Transaction<'_>,
    event: &str,
    actor: &str,
    job_id: Option<&str>,
    details: &Value,
) -> Result<()> {
    let previous_hash: String = transaction
        .query_row(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or_else(|| "0".repeat(64));
    let at = now().to_rfc3339();
    let details_json = String::from_utf8(canonical_json(details)?)
        .map_err(|_| Error::Protocol("audit JSON was not UTF-8".into()))?;
    let material = canonical_json(&json!({
        "at": at,
        "event": event,
        "actor": actor,
        "job_id": job_id,
        "details": details,
        "previous_hash": previous_hash,
    }))?;
    let entry_hash = sha256_hex(&material);
    transaction.execute(
        "INSERT INTO audit_log
         (at, event, actor, job_id, details_json, previous_hash, entry_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            at,
            event,
            actor,
            job_id,
            details_json,
            previous_hash,
            entry_hash
        ],
    )?;
    Ok(())
}

fn verify_audit_database(path: &Path) -> Result<u64> {
    let connection = open_database(path)?;
    let mut statement = connection.prepare(
        "SELECT id, at, event, actor, job_id, details_json, previous_hash, entry_hash
         FROM audit_log ORDER BY id ASC",
    )?;
    let mut rows = statement.query([])?;
    let mut previous = "0".repeat(64);
    let mut count = 0;
    while let Some(row) = rows.next()? {
        let id: u64 = row.get(0)?;
        let at: String = row.get(1)?;
        let event: String = row.get(2)?;
        let actor: String = row.get(3)?;
        let job_id: Option<String> = row.get(4)?;
        let details_json: String = row.get(5)?;
        let stored_previous: String = row.get(6)?;
        let stored_hash: String = row.get(7)?;
        if stored_previous != previous {
            return Err(Error::Crypto(format!(
                "audit chain breaks before entry {id}"
            )));
        }
        let details: Value = serde_json::from_str(&details_json)?;
        let material = canonical_json(&json!({
            "at": at, "event": event, "actor": actor,
            "job_id": job_id, "details": details, "previous_hash": previous,
        }))?;
        if sha256_hex(&material) != stored_hash {
            return Err(Error::Crypto(format!("audit entry {id} was modified")));
        }
        previous = stored_hash;
        count += 1;
    }
    Ok(count)
}

fn next_outbound_sequence(transaction: &Transaction<'_>, sender: &str) -> Result<u64> {
    let current: Option<u64> = transaction
        .query_row(
            "SELECT last_sequence FROM outbound_sequences WHERE sender_id = ?1",
            [sender],
            |row| row.get(0),
        )
        .optional()?;
    let next = current.unwrap_or(0).saturating_add(1);
    transaction.execute(
        "INSERT INTO outbound_sequences (sender_id, last_sequence) VALUES (?1, ?2)
         ON CONFLICT(sender_id) DO UPDATE SET last_sequence = excluded.last_sequence",
        params![sender, next],
    )?;
    Ok(next)
}

fn aggregate_status(results: &[NodeResult]) -> ExecutionStatus {
    if results
        .iter()
        .any(|result| result.status == ExecutionStatus::Uncertain)
    {
        ExecutionStatus::Uncertain
    } else if results
        .iter()
        .any(|result| result.status == ExecutionStatus::Failed)
    {
        ExecutionStatus::Failed
    } else if results
        .iter()
        .any(|result| result.status == ExecutionStatus::Rejected)
    {
        ExecutionStatus::Rejected
    } else {
        ExecutionStatus::Succeeded
    }
}
