use chrono::Duration;
use hailmary::model::{Attachment, ExecutionStatus, Job};
use hailmary::policy::{AgentPolicy, CommandProfile, FileTarget};
use hailmary::task::TaskEngine;
use hailmary::util::{now, sha256_hex};
use serde_json::{Map, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn policy(root: &Path) -> AgentPolicy {
    AgentPolicy {
        version: 1,
        allowed_actions: BTreeSet::from([
            "integrity.verify".into(),
            "file.deploy".into(),
            "config.apply".into(),
        ]),
        allowed_services: BTreeSet::new(),
        log_sources: BTreeMap::new(),
        integrity_roots: BTreeMap::from([("test".into(), root.to_path_buf())]),
        file_targets: BTreeMap::from([(
            "configuration".into(),
            FileTarget {
                path: root.join("config.txt"),
                mode: Some(0o600),
                validator: Some("reject".into()),
            },
        )]),
        backup_sources: BTreeMap::new(),
        backup_directory: None,
        staging_directory: None,
        command_profiles: BTreeMap::from([(
            "reject".into(),
            CommandProfile {
                program: PathBuf::from("/bin/false"),
                args: Vec::new(),
                timeout_seconds: 5,
            },
        )]),
        installer_profiles: BTreeMap::new(),
        patch_profiles: BTreeMap::new(),
        reboot_profile: None,
        redaction_patterns: Vec::new(),
        max_read_bytes: 1024 * 1024,
        max_artifact_bytes: 1024 * 1024,
        max_output_bytes: 1024,
    }
}

fn job(action: &str, params: &serde_json::Value, attachments: Vec<Attachment>) -> Job {
    let created = now();
    Job {
        job_id: format!("job-{}", action.replace('.', "-")),
        action: action.into(),
        targets: vec!["node-1".into()],
        params: params.as_object().cloned().unwrap_or_else(Map::new),
        attachments,
        dry_run: false,
        created_at: created,
        not_before: None,
        expires_at: created + Duration::hours(1),
    }
}

#[test]
fn integrity_task_rejects_path_traversal() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(temporary.path().join("safe.txt"), b"safe").unwrap();
    let policy = policy(temporary.path());
    let request = job(
        "integrity.verify",
        &json!({"root": "test", "files": {"../outside": "00"}}),
        Vec::new(),
    );
    let result = TaskEngine::new("node-1", &policy).execute(&request);
    assert_eq!(result.status, ExecutionStatus::Failed);
}

#[test]
#[cfg(unix)]
fn failed_configuration_validation_rolls_back() {
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("config.txt");
    fs::write(&target, b"original").unwrap();
    let policy = policy(temporary.path());
    let replacement = b"replacement";
    let request = job(
        "config.apply",
        &json!({
            "target": "configuration",
            "attachment": "config",
            "expected_sha256": sha256_hex(replacement),
        }),
        vec![Attachment::new(
            "config".into(),
            "application/octet-stream".into(),
            replacement,
        )],
    );
    let result = TaskEngine::new("node-1", &policy).execute(&request);
    assert_eq!(result.status, ExecutionStatus::Failed);
    assert!(result.rollback_performed);
    assert_eq!(fs::read(target).unwrap(), b"original");
}
