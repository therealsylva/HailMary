use crate::config::AgentConfig;
use crate::model::{ExecutionStatus, Job, NodeResult};
use crate::policy::AgentPolicy;
use crate::protocol::{AgentClient, AgentRequest, ControllerResponse};
use crate::task::TaskEngine;
use crate::util::{canonical_json, now};
use crate::{Error, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use std::fs;
use std::path::Path;

pub struct Agent {
    config: AgentConfig,
    policy: AgentPolicy,
    client: AgentClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleOutcome {
    Idle,
    ResultSubmitted,
}

impl Agent {
    pub fn load(config: AgentConfig) -> Result<Self> {
        let policy = AgentPolicy::read(&config.policy)?;
        initialize_journal(&config.state_database)?;
        let client = AgentClient::new(config.controller.clone())?;
        Ok(Self {
            config,
            policy,
            client,
        })
    }

    pub fn cycle(&self) -> Result<CycleOutcome> {
        if let Some(result) = self.pending_result()? {
            self.submit_result(&result)?;
            self.mark_acknowledged(&result.job_id)?;
            return Ok(CycleOutcome::ResultSubmitted);
        }
        let response = self.client.request(&AgentRequest::Claim {
            node_id: self.config.node_id.clone(),
        })?;
        match response {
            ControllerResponse::NoJob { .. } => Ok(CycleOutcome::Idle),
            ControllerResponse::Job { job } => {
                let result = self.execute_once(&job)?;
                self.submit_result(&result)?;
                self.mark_acknowledged(&job.job_id)?;
                Ok(CycleOutcome::ResultSubmitted)
            }
            ControllerResponse::Error { code, message } => Err(Error::Protocol(format!(
                "controller error {code}: {message}"
            ))),
            _ => Err(Error::Protocol(
                "controller returned an unexpected response".into(),
            )),
        }
    }

    pub fn poll_seconds(&self) -> u64 {
        self.config.controller.poll_seconds
    }

    fn execute_once(&self, job: &Job) -> Result<NodeResult> {
        if !job
            .targets
            .iter()
            .any(|target| target == &self.config.node_id)
        {
            return Err(Error::PolicyDenied(
                "controller dispatched a job for another node".into(),
            ));
        }
        let connection = open_journal(&self.config.state_database)?;
        let existing: Option<(String, Option<String>)> = connection
            .query_row(
                "SELECT state, result_json FROM executions WHERE job_id = ?1",
                [&job.job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((state, result)) = existing {
            if let Some(result) = result {
                return Ok(serde_json::from_str(&result)?);
            }
            if state == "running" {
                let result = NodeResult {
                    job_id: job.job_id.clone(),
                    node_id: self.config.node_id.clone(),
                    action: job.action.clone(),
                    status: ExecutionStatus::Uncertain,
                    started_at: now(),
                    completed_at: now(),
                    summary:
                        "agent restarted during execution; mutation was not replayed automatically"
                            .into(),
                    output: Value::Null,
                    artifacts: Vec::new(),
                    rollback_performed: false,
                };
                store_result(&connection, &result)?;
                return Ok(result);
            }
        }
        connection.execute(
            "INSERT INTO executions (job_id, action, state, started_at)
             VALUES (?1, ?2, 'running', ?3)",
            params![job.job_id, job.action, now().to_rfc3339()],
        )?;
        let result = TaskEngine::new(&self.config.node_id, &self.policy).execute(job);
        store_result(&connection, &result)?;
        Ok(result)
    }

    fn pending_result(&self) -> Result<Option<NodeResult>> {
        let connection = open_journal(&self.config.state_database)?;
        let result: Option<String> = connection
            .query_row(
                "SELECT result_json FROM executions
                 WHERE state = 'completed' ORDER BY completed_at ASC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        result
            .map(|result| serde_json::from_str(&result).map_err(Error::Json))
            .transpose()
    }

    fn submit_result(&self, result: &NodeResult) -> Result<()> {
        match self.client.request(&AgentRequest::Complete {
            node_id: self.config.node_id.clone(),
            result: result.clone(),
        })? {
            ControllerResponse::Accepted => Ok(()),
            ControllerResponse::Error { code, message } => Err(Error::Protocol(format!(
                "controller error {code}: {message}"
            ))),
            _ => Err(Error::Protocol(
                "controller did not acknowledge the result".into(),
            )),
        }
    }

    fn mark_acknowledged(&self, job_id: &str) -> Result<()> {
        open_journal(&self.config.state_database)?.execute(
            "UPDATE executions SET state = 'acknowledged' WHERE job_id = ?1",
            [job_id],
        )?;
        Ok(())
    }
}

fn initialize_journal(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let connection = open_journal(path)?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS executions (
            job_id TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            state TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            result_json TEXT
        );",
    )?;
    Ok(())
}

fn open_journal(path: &Path) -> Result<Connection> {
    let connection = Connection::open(path)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(connection)
}

fn store_result(connection: &Connection, result: &NodeResult) -> Result<()> {
    let result_json = String::from_utf8(canonical_json(result)?)
        .map_err(|_| Error::Protocol("result JSON was not UTF-8".into()))?;
    connection.execute(
        "UPDATE executions SET state = 'completed', completed_at = ?2, result_json = ?3
         WHERE job_id = ?1",
        params![result.job_id, result.completed_at.to_rfc3339(), result_json],
    )?;
    Ok(())
}
