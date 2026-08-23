use crate::model::{Attachment, ExecutionStatus, Job, NodeResult, RiskLevel};
use crate::policy::{AgentPolicy, CommandProfile, FileTarget};
use crate::util::{
    atomic_write, confined_path, now, read_limited, sha256_hex, validate_relative_path,
};
use crate::{Error, Result};
use flate2::Compression;
use flate2::write::GzEncoder;
use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use sysinfo::{Disks, System};
use wait_timeout::ChildExt;

pub const ACTIONS: &[(&str, RiskLevel)] = &[
    ("inventory.collect", RiskLevel::ReadOnly),
    ("health.collect", RiskLevel::ReadOnly),
    ("logs.collect", RiskLevel::ReadOnly),
    ("integrity.verify", RiskLevel::ReadOnly),
    ("service.status", RiskLevel::ReadOnly),
    ("config.audit", RiskLevel::ReadOnly),
    ("file.retrieve", RiskLevel::ReadOnly),
    ("service.restart", RiskLevel::Reversible),
    ("config.apply", RiskLevel::Reversible),
    ("file.deploy", RiskLevel::Reversible),
    ("package.install", RiskLevel::Disruptive),
    ("patch.apply", RiskLevel::Disruptive),
    ("backup.create", RiskLevel::Reversible),
    ("system.reboot", RiskLevel::Critical),
];

pub fn action_risk(action: &str) -> Option<RiskLevel> {
    ACTIONS
        .iter()
        .find_map(|(candidate, risk)| (*candidate == action).then_some(*risk))
}

pub struct TaskEngine<'a> {
    node_id: &'a str,
    policy: &'a AgentPolicy,
}

impl<'a> TaskEngine<'a> {
    pub fn new(node_id: &'a str, policy: &'a AgentPolicy) -> Self {
        Self { node_id, policy }
    }

    pub fn execute(&self, job: &Job) -> NodeResult {
        let started_at = now();
        let result = self.execute_inner(job);
        let completed_at = now();
        match result {
            Ok(task) => NodeResult {
                job_id: job.job_id.clone(),
                node_id: self.node_id.into(),
                action: job.action.clone(),
                status: task.status,
                started_at,
                completed_at,
                summary: task.summary,
                output: task.output,
                artifacts: task.artifacts,
                rollback_performed: task.rollback_performed,
            },
            Err(error) => NodeResult {
                job_id: job.job_id.clone(),
                node_id: self.node_id.into(),
                action: job.action.clone(),
                status: if matches!(error, Error::PolicyDenied(_)) {
                    ExecutionStatus::Rejected
                } else {
                    ExecutionStatus::Failed
                },
                started_at,
                completed_at,
                summary: error.to_string(),
                output: Value::Null,
                artifacts: Vec::new(),
                rollback_performed: false,
            },
        }
    }

    fn execute_inner(&self, job: &Job) -> Result<TaskOutput> {
        self.policy.ensure_action(&job.action)?;
        if action_risk(&job.action).is_none() {
            return Err(Error::InvalidInput(format!(
                "unsupported action {}",
                job.action
            )));
        }
        match job.action.as_str() {
            "inventory.collect" => Ok(Self::inventory()),
            "health.collect" => Ok(Self::health()),
            "logs.collect" => self.logs(job),
            "integrity.verify" => self.integrity(job),
            "service.status" => self.service(job, false),
            "service.restart" => self.service(job, true),
            "config.audit" => self.config_audit(job),
            "config.apply" => self.deploy(job, true),
            "file.deploy" => self.deploy(job, false),
            "file.retrieve" => self.retrieve(job),
            "package.install" => self.install(job),
            "patch.apply" => self.patch(job),
            "backup.create" => self.backup(job),
            "system.reboot" => self.reboot(job),
            _ => Err(Error::InvalidInput("unsupported action".into())),
        }
    }

    fn inventory() -> TaskOutput {
        let mut system = System::new_all();
        system.refresh_all();
        let disks = Disks::new_with_refreshed_list();
        let disk_data: Vec<Value> = disks
            .iter()
            .map(|disk| {
                json!({
                    "name": disk.name().to_string_lossy(),
                    "mount_point": disk.mount_point(),
                    "file_system": disk.file_system().to_string_lossy(),
                    "total_bytes": disk.total_space(),
                    "available_bytes": disk.available_space(),
                })
            })
            .collect();
        TaskOutput::new(
            "inventory collected",
            json!({
                "hostname": System::host_name(),
                "os": System::name(),
                "os_version": System::os_version(),
                "kernel_version": System::kernel_version(),
                "architecture": std::env::consts::ARCH,
                "cpu_count": system.cpus().len(),
                "total_memory_bytes": system.total_memory(),
                "disks": disk_data,
            }),
        )
    }

    fn health() -> TaskOutput {
        let mut system = System::new_all();
        system.refresh_all();
        let disks = Disks::new_with_refreshed_list();
        let load = System::load_average();
        TaskOutput::new(
            "health collected",
            json!({
                "uptime_seconds": System::uptime(),
                "load_average": {"one": load.one, "five": load.five, "fifteen": load.fifteen},
                "used_memory_bytes": system.used_memory(),
                "total_memory_bytes": system.total_memory(),
                "process_count": system.processes().len(),
                "disk_free_bytes": disks.iter().map(sysinfo::Disk::available_space).sum::<u64>(),
                "disk_total_bytes": disks.iter().map(sysinfo::Disk::total_space).sum::<u64>(),
            }),
        )
    }

    fn logs(&self, job: &Job) -> Result<TaskOutput> {
        let request: LogRequest = params(job)?;
        let path = self
            .policy
            .log_sources
            .get(&request.source)
            .ok_or_else(|| Error::PolicyDenied(format!("unknown log source {}", request.source)))?;
        let requested = request.max_bytes.unwrap_or(self.policy.max_read_bytes);
        let max_bytes = requested.min(self.policy.max_read_bytes);
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(Error::UnsafePath(path.clone()));
        }
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        if length > max_bytes {
            file.seek(SeekFrom::End(-i64::try_from(max_bytes).unwrap_or(i64::MAX)))?;
        }
        let mut bytes = Vec::new();
        file.take(max_bytes).read_to_end(&mut bytes)?;
        let content = redact(&String::from_utf8_lossy(&bytes), &self.policy.redactors()?);
        Ok(TaskOutput::new(
            "log data collected",
            json!({"source": request.source, "content": content, "truncated": length > max_bytes}),
        ))
    }

    fn integrity(&self, job: &Job) -> Result<TaskOutput> {
        let request: IntegrityRequest = params(job)?;
        let root = self
            .policy
            .integrity_roots
            .get(&request.root)
            .ok_or_else(|| {
                Error::PolicyDenied(format!("unknown integrity root {}", request.root))
            })?;
        let mut results = Map::new();
        for (relative, expected) in request.files {
            if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(Error::InvalidInput(format!(
                    "invalid SHA-256 digest for {relative}"
                )));
            }
            let relative_path = Path::new(&relative);
            validate_relative_path(relative_path)?;
            let candidate = confined_path(root, relative_path)?;
            let result = if candidate.is_file() {
                let bytes = read_limited(&candidate, self.policy.max_read_bytes)?;
                let actual = sha256_hex(&bytes);
                json!({"expected": expected, "actual": actual, "matches": actual == expected})
            } else {
                json!({"expected": expected, "missing": true, "matches": false})
            };
            results.insert(relative, result);
        }
        let matches = results
            .values()
            .all(|value| value.get("matches").and_then(Value::as_bool) == Some(true));
        Ok(TaskOutput::new(
            if matches {
                "integrity verified"
            } else {
                "integrity mismatch detected"
            },
            json!({"root": request.root, "matches": matches, "files": results}),
        ))
    }

    fn service(&self, job: &Job, restart: bool) -> Result<TaskOutput> {
        let request: ServiceRequest = params(job)?;
        if !self.policy.allowed_services.contains(&request.name) {
            return Err(Error::PolicyDenied(format!(
                "service {} is not allowlisted",
                request.name
            )));
        }
        if restart && job.dry_run {
            return Ok(TaskOutput::new(
                "dry run: service would be restarted",
                json!({"service": request.name}),
            ));
        }
        let operation = if restart { "restart" } else { "status" };
        let commands: Vec<(&str, Vec<String>)> = if cfg!(target_os = "windows") {
            if restart {
                vec![
                    ("sc.exe", vec!["stop".into(), request.name.clone()]),
                    ("sc.exe", vec!["start".into(), request.name.clone()]),
                ]
            } else {
                vec![("sc.exe", vec!["query".into(), request.name.clone()])]
            }
        } else if cfg!(target_os = "macos") {
            vec![(
                "/bin/launchctl",
                if restart {
                    vec![
                        "kickstart".into(),
                        "-k".into(),
                        format!("system/{}", request.name),
                    ]
                } else {
                    vec!["print".into(), format!("system/{}", request.name)]
                },
            )]
        } else {
            vec![(
                "/usr/bin/systemctl",
                vec![operation.into(), request.name.clone(), "--no-pager".into()],
            )]
        };
        let redactors = self.policy.redactors()?;
        let mut outputs = Vec::with_capacity(commands.len());
        for (program, args) in commands {
            let output = run_command(
                Path::new(program),
                &args,
                120,
                self.policy.max_output_bytes,
                &redactors,
            )?;
            if output.exit_code != 0 {
                return Err(Error::InvalidInput(format!(
                    "service command failed: {}",
                    output.stderr
                )));
            }
            outputs.push(output);
        }
        Ok(TaskOutput::new(
            format!("service {operation} completed"),
            serde_json::to_value(outputs)?,
        ))
    }

    fn config_audit(&self, job: &Job) -> Result<TaskOutput> {
        let request: TargetRequest = params(job)?;
        let target = self.file_target(&request.target)?;
        let bytes = read_limited(&target.path, self.policy.max_read_bytes)?;
        Ok(TaskOutput::new(
            "configuration audited",
            json!({
                "target": request.target,
                "sha256": sha256_hex(&bytes),
                "size_bytes": bytes.len(),
            }),
        ))
    }

    fn deploy(&self, job: &Job, validate: bool) -> Result<TaskOutput> {
        let request: DeployRequest = params(job)?;
        let target = self.file_target(&request.target)?.clone();
        let bytes = job.attachment(&request.attachment, self.policy.max_artifact_bytes)?;
        if let Some(expected) = &request.expected_sha256
            && expected != &sha256_hex(&bytes)
        {
            return Err(Error::Crypto(
                "deployment digest does not match request".into(),
            ));
        }
        if job.dry_run {
            return Ok(TaskOutput::new(
                "dry run: file would be deployed",
                json!({"target": request.target, "sha256": sha256_hex(&bytes)}),
            ));
        }
        if fs::symlink_metadata(&target.path)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(Error::UnsafePath(target.path));
        }
        #[cfg(unix)]
        let previous_mode = fs::metadata(&target.path).ok().map(|metadata| {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o7777
        });
        #[cfg(not(unix))]
        let previous_mode = None;
        let previous = target
            .path
            .exists()
            .then(|| fs::read(&target.path))
            .transpose()?;
        atomic_write(&target.path, &bytes, true)?;
        apply_mode(&target, previous_mode)?;
        if validate && let Some(profile_name) = &target.validator {
            let profile = self
                .policy
                .command_profiles
                .get(profile_name)
                .ok_or_else(|| Error::PolicyDenied(format!("unknown validator {profile_name}")))?;
            let placeholders = [("path", target.path.to_string_lossy().into_owned())];
            let command = run_profile(
                profile,
                &placeholders,
                self.policy.max_output_bytes,
                &self.policy.redactors()?,
            )?;
            if command.exit_code != 0 {
                let rollback_performed = if let Some(previous) = previous {
                    atomic_write(&target.path, &previous, true)?;
                    apply_mode(&target, previous_mode)?;
                    true
                } else {
                    fs::remove_file(&target.path)?;
                    true
                };
                return Ok(TaskOutput {
                    status: ExecutionStatus::Failed,
                    summary: "configuration validation failed; previous content restored".into(),
                    output: serde_json::to_value(command)?,
                    artifacts: Vec::new(),
                    rollback_performed,
                });
            }
        }
        Ok(TaskOutput::new(
            "file deployed atomically",
            json!({"target": request.target, "sha256": sha256_hex(&bytes), "size_bytes": bytes.len()}),
        ))
    }

    fn retrieve(&self, job: &Job) -> Result<TaskOutput> {
        let request: TargetRequest = params(job)?;
        let target = self.file_target(&request.target)?;
        let bytes = read_limited(&target.path, self.policy.max_artifact_bytes as u64)?;
        Ok(TaskOutput {
            status: ExecutionStatus::Succeeded,
            summary: "file retrieved".into(),
            output: json!({"target": request.target, "sha256": sha256_hex(&bytes)}),
            artifacts: vec![Attachment::new(
                request.target,
                "application/octet-stream".into(),
                &bytes,
            )],
            rollback_performed: false,
        })
    }

    fn install(&self, job: &Job) -> Result<TaskOutput> {
        let request: InstallRequest = params(job)?;
        let profile = self
            .policy
            .installer_profiles
            .get(&request.profile)
            .ok_or_else(|| {
                Error::PolicyDenied(format!("unknown installer profile {}", request.profile))
            })?;
        let bytes = job.attachment(&request.attachment, self.policy.max_artifact_bytes)?;
        if job.dry_run {
            return Ok(TaskOutput::new(
                "dry run: package would be installed",
                json!({"profile": request.profile, "sha256": sha256_hex(&bytes)}),
            ));
        }
        let staging = self
            .policy
            .staging_directory
            .as_ref()
            .ok_or_else(|| Error::PolicyDenied("no staging directory configured".into()))?;
        fs::create_dir_all(staging)?;
        let artifact_path = staging.join(format!("{}-{}", job.job_id, request.attachment));
        atomic_write(&artifact_path, &bytes, true)?;
        let placeholders = [("artifact", artifact_path.to_string_lossy().into_owned())];
        let output = run_profile(
            profile,
            &placeholders,
            self.policy.max_output_bytes,
            &self.policy.redactors()?,
        );
        let cleanup = fs::remove_file(&artifact_path);
        if let Err(error) = cleanup {
            return Err(Error::Io(error));
        }
        let output = output?;
        if output.exit_code != 0 {
            return Err(Error::InvalidInput(format!(
                "installer failed: {}",
                output.stderr
            )));
        }
        Ok(TaskOutput::new(
            "package installed",
            serde_json::to_value(output)?,
        ))
    }

    fn patch(&self, job: &Job) -> Result<TaskOutput> {
        let request: ProfileRequest = params(job)?;
        let profile = self
            .policy
            .patch_profiles
            .get(&request.profile)
            .ok_or_else(|| {
                Error::PolicyDenied(format!("unknown patch profile {}", request.profile))
            })?;
        if job.dry_run {
            return Ok(TaskOutput::new(
                "dry run: patch profile would run",
                json!({"profile": request.profile}),
            ));
        }
        let output = run_profile(
            profile,
            &[],
            self.policy.max_output_bytes,
            &self.policy.redactors()?,
        )?;
        if output.exit_code != 0 {
            return Err(Error::InvalidInput(format!(
                "patch profile failed: {}",
                output.stderr
            )));
        }
        Ok(TaskOutput::new(
            "patch profile completed",
            serde_json::to_value(output)?,
        ))
    }

    fn backup(&self, job: &Job) -> Result<TaskOutput> {
        let request: BackupRequest = params(job)?;
        let source = self
            .policy
            .backup_sources
            .get(&request.source)
            .ok_or_else(|| {
                Error::PolicyDenied(format!("unknown backup source {}", request.source))
            })?;
        if job.dry_run {
            return Ok(TaskOutput::new(
                "dry run: backup would be created",
                json!({"source": request.source}),
            ));
        }
        let directory = self
            .policy
            .backup_directory
            .as_ref()
            .ok_or_else(|| Error::PolicyDenied("no backup directory configured".into()))?;
        fs::create_dir_all(directory)?;
        let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
        {
            let encoder = GzEncoder::new(temporary.as_file_mut(), Compression::default());
            let mut archive = tar::Builder::new(encoder);
            archive.follow_symlinks(false);
            if source.is_dir() {
                archive.append_dir_all(&request.source, source)?;
            } else {
                archive.append_path_with_name(source, &request.source)?;
            }
            let encoder = archive.into_inner()?;
            encoder.finish()?;
        }
        let size = temporary.as_file().metadata()?.len();
        if size > self.policy.max_artifact_bytes as u64 {
            return Err(Error::InvalidInput(
                "backup exceeds the configured artifact limit".into(),
            ));
        }
        temporary.as_file_mut().seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        temporary.as_file_mut().read_to_end(&mut bytes)?;
        Ok(TaskOutput {
            status: ExecutionStatus::Succeeded,
            summary: "backup created".into(),
            output: json!({"source": request.source, "sha256": sha256_hex(&bytes), "size_bytes": bytes.len()}),
            artifacts: vec![Attachment::new(
                format!("backup-{}.tar.gz", request.source),
                "application/gzip".into(),
                &bytes,
            )],
            rollback_performed: false,
        })
    }

    fn reboot(&self, job: &Job) -> Result<TaskOutput> {
        let profile = self
            .policy
            .reboot_profile
            .as_ref()
            .ok_or_else(|| Error::PolicyDenied("reboot is not configured".into()))?;
        if job.dry_run {
            return Ok(TaskOutput::new("dry run: system would reboot", Value::Null));
        }
        let output = run_profile(
            profile,
            &[],
            self.policy.max_output_bytes,
            &self.policy.redactors()?,
        )?;
        if output.exit_code != 0 {
            return Err(Error::InvalidInput(format!(
                "reboot command failed: {}",
                output.stderr
            )));
        }
        Ok(TaskOutput::new(
            "reboot command accepted",
            serde_json::to_value(output)?,
        ))
    }

    fn file_target(&self, alias: &str) -> Result<&FileTarget> {
        self.policy
            .file_targets
            .get(alias)
            .ok_or_else(|| Error::PolicyDenied(format!("unknown file target {alias}")))
    }
}

#[derive(Debug)]
struct TaskOutput {
    status: ExecutionStatus,
    summary: String,
    output: Value,
    artifacts: Vec<Attachment>,
    rollback_performed: bool,
}

impl TaskOutput {
    fn new(summary: impl Into<String>, output: Value) -> Self {
        Self {
            status: ExecutionStatus::Succeeded,
            summary: summary.into(),
            output,
            artifacts: Vec::new(),
            rollback_performed: false,
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct CommandOutput {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogRequest {
    source: String,
    max_bytes: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntegrityRequest {
    root: String,
    files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceRequest {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetRequest {
    target: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeployRequest {
    target: String,
    attachment: String,
    expected_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallRequest {
    profile: String,
    attachment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileRequest {
    profile: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupRequest {
    source: String,
}

fn params<T: for<'de> Deserialize<'de>>(job: &Job) -> Result<T> {
    serde_json::from_value(Value::Object(job.params.clone())).map_err(Error::Json)
}

fn redact(value: &str, patterns: &[Regex]) -> String {
    patterns.iter().fold(value.to_owned(), |current, pattern| {
        pattern.replace_all(&current, "[REDACTED]").into_owned()
    })
}

fn run_profile(
    profile: &CommandProfile,
    placeholders: &[(&str, String)],
    max_output_bytes: usize,
    redactors: &[Regex],
) -> Result<CommandOutput> {
    let args: Vec<String> = profile
        .args
        .iter()
        .map(|argument| {
            placeholders
                .iter()
                .fold(argument.clone(), |value, (name, replacement)| {
                    value.replace(&format!("{{{name}}}"), replacement)
                })
        })
        .collect();
    run_command(
        &profile.program,
        &args,
        profile.timeout_seconds,
        max_output_bytes,
        redactors,
    )
}

fn run_command(
    program: &Path,
    args: &[String],
    timeout_seconds: u64,
    max_output_bytes: usize,
    redactors: &[Regex],
) -> Result<CommandOutput> {
    if !program.is_absolute() && program.components().count() > 1 {
        return Err(Error::PolicyDenied(
            "command program must be an absolute path or fixed executable name".into(),
        ));
    }
    let stdout_file = tempfile::tempfile()?;
    let stderr_file = tempfile::tempfile()?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file.try_clone()?))
        .stderr(Stdio::from(stderr_file.try_clone()?))
        .spawn()?;
    let Some(status) = child.wait_timeout(Duration::from_secs(timeout_seconds))? else {
        child.kill()?;
        child.wait()?;
        return Err(Error::Timeout(timeout_seconds));
    };
    let read_output = |mut file: File| -> Result<String> {
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.take(max_output_bytes as u64).read_to_end(&mut bytes)?;
        Ok(redact(&String::from_utf8_lossy(&bytes), redactors))
    };
    Ok(CommandOutput {
        exit_code: status.code().unwrap_or(-1),
        stdout: read_output(stdout_file)?,
        stderr: read_output(stderr_file)?,
    })
}

fn apply_mode(target: &FileTarget, previous_mode: Option<u32>) -> Result<()> {
    #[cfg(unix)]
    if let Some(mode) = target.mode.or(previous_mode) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target.path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (target, previous_mode);
    Ok(())
}
