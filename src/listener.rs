use crate::bundle::Bundle;
use crate::config::ListenerConfig;
use crate::controller::Controller;
use crate::util::{atomic_write, now, read_limited, sha256_hex};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

const RECEIPT_FORMAT: &str = "hailmary.ingress-receipt";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ListenerEvent {
    Imported {
        source: String,
        archived: String,
        sha256: String,
        job_id: String,
        already_imported: bool,
    },
    Rejected {
        source: String,
        quarantined: Option<String>,
        sha256: Option<String>,
        error: String,
    },
    Deferred {
        source: String,
        staged: String,
        sha256: String,
        reason: String,
    },
    InboxUnavailable {
        inbox: String,
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    length: u64,
    modified: Option<SystemTime>,
}

#[derive(Debug)]
struct Candidate {
    fingerprint: Fingerprint,
    stable_since: Instant,
    processed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingSource {
    source: String,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct IngressReceipt<'a> {
    format: &'static str,
    version: u32,
    outcome: &'a str,
    source: &'a str,
    sha256: &'a str,
    archived_bundle: String,
    processed_at: String,
    job_id: Option<&'a str>,
    already_imported: Option<bool>,
    error: Option<&'a str>,
}

pub struct Listener {
    controller: Arc<Controller>,
    config: ListenerConfig,
    candidates: HashMap<PathBuf, Candidate>,
    unavailable_inboxes: HashSet<PathBuf>,
    deferred: HashSet<String>,
}

impl Listener {
    pub fn new(controller: Arc<Controller>) -> Result<Self> {
        let config = controller
            .config
            .listener
            .clone()
            .filter(|config| config.enabled)
            .ok_or_else(|| Error::InvalidInput("controller listener is not enabled".into()))?;
        prepare_state_directory(&config)?;
        Ok(Self {
            controller,
            config,
            candidates: HashMap::new(),
            unavailable_inboxes: HashSet::new(),
            deferred: HashSet::new(),
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn scan_once(&mut self) -> Result<Vec<ListenerEvent>> {
        let mut events = self.recover_pending()?;
        let mut seen = HashSet::new();
        let mut ready = Vec::new();

        let inboxes = self.config.inboxes.clone();
        for inbox in &inboxes {
            let metadata = match fs::symlink_metadata(inbox) {
                Ok(metadata) if metadata.file_type().is_dir() => metadata,
                Ok(_) => {
                    self.report_unavailable(
                        inbox,
                        "configured inbox is not a directory",
                        &mut events,
                    );
                    continue;
                }
                Err(error) => {
                    self.report_unavailable(inbox, &error.to_string(), &mut events);
                    continue;
                }
            };
            if metadata.file_type().is_symlink() {
                self.report_unavailable(
                    inbox,
                    "configured inbox must not be a symbolic link",
                    &mut events,
                );
                continue;
            }
            self.unavailable_inboxes.remove(inbox);
            let entries = match fs::read_dir(inbox) {
                Ok(entries) => entries,
                Err(error) => {
                    self.report_unavailable(inbox, &error.to_string(), &mut events);
                    continue;
                }
            };

            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        self.report_unavailable(inbox, &error.to_string(), &mut events);
                        continue;
                    }
                };
                let path = entry.path();
                if !has_hail_extension(&path) {
                    continue;
                }
                seen.insert(path.clone());
                let metadata = match fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.file_type().is_file() => metadata,
                    Ok(_) => {
                        let candidate = self.candidates.entry(path.clone()).or_insert(Candidate {
                            fingerprint: Fingerprint {
                                length: 0,
                                modified: None,
                            },
                            stable_since: Instant::now(),
                            processed: false,
                        });
                        if !candidate.processed {
                            events.push(ListenerEvent::Rejected {
                                source: display(&path),
                                quarantined: None,
                                sha256: None,
                                error: "inbox entry is not a regular file".into(),
                            });
                            candidate.processed = true;
                        }
                        continue;
                    }
                    Err(error) => {
                        events.push(ListenerEvent::Rejected {
                            source: display(&path),
                            quarantined: None,
                            sha256: None,
                            error: error.to_string(),
                        });
                        continue;
                    }
                };
                let fingerprint = Fingerprint {
                    length: metadata.len(),
                    modified: metadata.modified().ok(),
                };
                let current = self.candidates.entry(path.clone()).or_insert(Candidate {
                    fingerprint: fingerprint.clone(),
                    stable_since: Instant::now(),
                    processed: false,
                });
                if current.fingerprint != fingerprint {
                    *current = Candidate {
                        fingerprint,
                        stable_since: Instant::now(),
                        processed: false,
                    };
                }
                if !current.processed
                    && current.stable_since.elapsed()
                        >= Duration::from_secs(self.config.settle_seconds)
                {
                    ready.push(path);
                }
            }
        }

        self.candidates.retain(|path, _| seen.contains(path));
        for path in ready {
            let mark_processed = match self.stage_candidate(&path) {
                Ok((Some(event), processed)) => {
                    events.push(event);
                    processed
                }
                Ok((None, processed)) => processed,
                Err(error) => {
                    events.push(ListenerEvent::Rejected {
                        source: display(&path),
                        quarantined: None,
                        sha256: None,
                        error: error.to_string(),
                    });
                    true
                }
            };
            if mark_processed {
                if let Some(candidate) = self.candidates.get_mut(&path) {
                    candidate.processed = true;
                }
            }
        }
        Ok(events)
    }

    pub fn run(mut self) -> Result<()> {
        loop {
            match self.scan_once() {
                Ok(events) => {
                    for event in events {
                        match serde_json::to_string(&event) {
                            Ok(line) => eprintln!("{line}"),
                            Err(error) => eprintln!("listener event serialization failed: {error}"),
                        }
                    }
                }
                Err(error) => eprintln!("listener scan failed: {error}"),
            }
            thread::sleep(Duration::from_secs(self.config.poll_seconds));
        }
    }

    fn report_unavailable(&mut self, inbox: &Path, error: &str, events: &mut Vec<ListenerEvent>) {
        if self.unavailable_inboxes.insert(inbox.to_path_buf()) {
            events.push(ListenerEvent::InboxUnavailable {
                inbox: display(inbox),
                error: error.into(),
            });
        }
    }

    fn stage_candidate(&mut self, source: &Path) -> Result<(Option<ListenerEvent>, bool)> {
        let before = fs::symlink_metadata(source)?;
        if !before.file_type().is_file() {
            return Err(Error::UnsafePath(source.to_path_buf()));
        }
        let bytes = read_limited(source, self.config.max_bundle_bytes)?;
        let after = fs::symlink_metadata(source)?;
        if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
            if let Some(candidate) = self.candidates.get_mut(source) {
                candidate.fingerprint = Fingerprint {
                    length: after.len(),
                    modified: after.modified().ok(),
                };
                candidate.stable_since = Instant::now();
                candidate.processed = false;
            }
            return Ok((None, false));
        }

        let digest = sha256_hex(&bytes);
        if self.final_bundle_path("accepted", &digest).exists()
            || self.final_bundle_path("rejected", &digest).exists()
            || self.pending_path(&digest).exists()
        {
            return Ok((None, true));
        }

        let pending = self.pending_path(&digest);
        atomic_write(&pending, &bytes, true)?;
        let source_record = PendingSource {
            source: display(source),
            sha256: digest.clone(),
        };
        atomic_write(
            &self.pending_source_path(&digest),
            &serde_json::to_vec(&source_record)?,
            true,
        )?;
        Ok((
            self.process_pending(&pending, &digest, &source_record.source)?,
            true,
        ))
    }

    fn recover_pending(&mut self) -> Result<Vec<ListenerEvent>> {
        let pending_directory = self.config.state_directory.join("pending");
        let mut paths = fs::read_dir(&pending_directory)?
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .filter(|path| has_hail_extension(path))
            .collect::<Vec<_>>();
        paths.sort();
        let mut events = Vec::new();
        for path in paths {
            let Some(digest) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                continue;
            }
            let source = self.pending_source(digest);
            if let Some(event) = self.process_pending(&path, digest, &source)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    fn process_pending(
        &mut self,
        pending: &Path,
        digest: &str,
        source: &str,
    ) -> Result<Option<ListenerEvent>> {
        let result = Bundle::read(pending).and_then(|bundle| {
            let actual = sha256_hex(&read_limited(pending, self.config.max_bundle_bytes)?);
            if actual != digest {
                return Err(Error::Crypto("staged bundle digest changed".into()));
            }
            self.controller.import_hail_idempotent(&bundle)
        });

        match result {
            Ok(outcome) => {
                self.deferred.remove(digest);
                let archived = self.finalize(
                    pending,
                    digest,
                    source,
                    "accepted",
                    Some(&outcome.job_id),
                    Some(outcome.already_imported),
                    None,
                )?;
                Ok(Some(ListenerEvent::Imported {
                    source: source.into(),
                    archived: display(&archived),
                    sha256: digest.into(),
                    job_id: outcome.job_id,
                    already_imported: outcome.already_imported,
                }))
            }
            Err(error) if retryable(&error) => {
                let first_report = self.deferred.insert(digest.into());
                Ok(first_report.then(|| ListenerEvent::Deferred {
                    source: source.into(),
                    staged: display(pending),
                    sha256: digest.into(),
                    reason: error.to_string(),
                }))
            }
            Err(error) => {
                self.deferred.remove(digest);
                let message = error.to_string();
                let quarantined = self.finalize(
                    pending,
                    digest,
                    source,
                    "rejected",
                    None,
                    None,
                    Some(&message),
                )?;
                Ok(Some(ListenerEvent::Rejected {
                    source: source.into(),
                    quarantined: Some(display(&quarantined)),
                    sha256: Some(digest.into()),
                    error: message,
                }))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize(
        &self,
        pending: &Path,
        digest: &str,
        source: &str,
        outcome: &str,
        job_id: Option<&str>,
        already_imported: Option<bool>,
        error: Option<&str>,
    ) -> Result<PathBuf> {
        let archived = self.final_bundle_path(outcome, digest);
        let receipt = IngressReceipt {
            format: RECEIPT_FORMAT,
            version: 1,
            outcome,
            source,
            sha256: digest,
            archived_bundle: display(&archived),
            processed_at: now().to_rfc3339(),
            job_id,
            already_imported,
            error,
        };
        let receipt_bytes = serde_json::to_vec_pretty(&receipt)?;
        atomic_write(&self.receipt_path(digest), &receipt_bytes, true)?;
        if archived.exists() {
            fs::remove_file(pending)?;
        } else {
            fs::rename(pending, &archived)?;
        }
        let source_record = self.pending_source_path(digest);
        if source_record.exists() {
            fs::remove_file(source_record)?;
        }
        Ok(archived)
    }

    fn pending_source(&self, digest: &str) -> String {
        let path = self.pending_source_path(digest);
        read_limited(&path, 16 * 1024)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<PendingSource>(&bytes).ok())
            .filter(|record| record.sha256 == digest)
            .map_or_else(|| "recovered-local-spool".into(), |record| record.source)
    }

    fn pending_path(&self, digest: &str) -> PathBuf {
        self.config
            .state_directory
            .join("pending")
            .join(format!("{digest}.hail"))
    }

    fn pending_source_path(&self, digest: &str) -> PathBuf {
        self.config
            .state_directory
            .join("pending")
            .join(format!("{digest}.source.json"))
    }

    fn final_bundle_path(&self, outcome: &str, digest: &str) -> PathBuf {
        self.config
            .state_directory
            .join(outcome)
            .join(format!("{digest}.hail"))
    }

    fn receipt_path(&self, digest: &str) -> PathBuf {
        self.config
            .state_directory
            .join("receipts")
            .join(format!("{digest}.json"))
    }
}

pub fn spawn(controller: Arc<Controller>) -> Result<()> {
    let listener = Listener::new(controller)?;
    thread::Builder::new()
        .name("hailmary-ingress-listener".into())
        .spawn(move || {
            if let Err(error) = listener.run() {
                eprintln!("listener stopped: {error}");
            }
        })
        .map_err(Error::Io)?;
    Ok(())
}

pub fn prepare_state_directory(config: &ListenerConfig) -> Result<()> {
    ensure_directory(&config.state_directory)?;
    for name in ["pending", "accepted", "rejected", "receipts"] {
        ensure_directory(&config.state_directory.join(name))?;
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(Error::UnsafePath(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn retryable(error: &Error) -> bool {
    matches!(
        error,
        Error::Io(_) | Error::Database(_) | Error::NotYetValid(_)
    )
}

fn has_hail_extension(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension == "hail")
}

fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
