use chrono::{DateTime, Duration, Utc};
use clap::{Args, Parser, Subcommand};
use hailmary::agent::{Agent, CycleOutcome};
use hailmary::bundle::{Bundle, BundleKind};
use hailmary::config::{AgentConfig, ControllerConfig};
use hailmary::controller::Controller;
use hailmary::crypto::clear_password;
use hailmary::identity::{Identity, PublicIdentity};
use hailmary::model::{Attachment, Job, RiskLevel};
use hailmary::task::ACTIONS;
use hailmary::trust::{TrustRole, TrustStore};
use hailmary::util::{now, parse_duration_seconds, read_limited, sha256_hex};
use hailmary::{Error, Result, VERSION};
use rusqlite::{Connection, OptionalExtension};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration as StdDuration;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "hailmary", version = VERSION, about = "Offline-first management for air-gapped networks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Identity(IdentityArgs),
    Trust(TrustArgs),
    Job(JobArgs),
    Bundle(BundleArgs),
    Controller(ControllerArgs),
    Agent(AgentArgs),
    Certificate(CertificateArgs),
    Actions,
}

#[derive(Debug, Args)]
struct IdentityArgs {
    #[command(subcommand)]
    command: IdentityCommand,
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    Generate {
        #[arg(long)]
        id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        password_file: PathBuf,
    },
    Show {
        #[arg(long)]
        identity: PathBuf,
    },
}

#[derive(Debug, Args)]
struct TrustArgs {
    #[command(subcommand)]
    command: TrustCommand,
}

#[derive(Debug, Subcommand)]
enum TrustCommand {
    Init {
        #[arg(long)]
        store: PathBuf,
    },
    Add {
        #[arg(long)]
        store: PathBuf,
        #[arg(long = "public")]
        public_identity: PathBuf,
        #[arg(long, value_enum)]
        role: TrustRole,
        #[arg(long = "action", required = true)]
        actions: Vec<String>,
        #[arg(long, value_enum)]
        max_risk: RiskLevel,
    },
    Revoke {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        key_id: String,
    },
    List {
        #[arg(long)]
        store: PathBuf,
    },
}

#[derive(Debug, Args)]
struct JobArgs {
    #[command(subcommand)]
    command: JobCommand,
}

#[derive(Debug, Subcommand)]
enum JobCommand {
    Create {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        password_file: PathBuf,
        #[arg(long = "recipient", required = true)]
        recipients: Vec<PathBuf>,
        #[arg(long)]
        action: String,
        #[arg(long = "target", required = true)]
        targets: Vec<String>,
        #[arg(long)]
        params: Option<PathBuf>,
        #[arg(long = "attachment", value_name = "NAME=PATH")]
        attachments: Vec<String>,
        #[arg(long)]
        job_id: Option<String>,
        #[arg(long)]
        sequence: Option<u64>,
        #[arg(long, default_value = "24h")]
        expires_in: String,
        #[arg(long)]
        not_before: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Args)]
struct BundleArgs {
    #[command(subcommand)]
    command: BundleCommand,
}

#[derive(Debug, Subcommand)]
enum BundleCommand {
    Inspect {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long, requires = "identity")]
        password_file: Option<PathBuf>,
        #[arg(long)]
        trust: Option<PathBuf>,
    },
    Verify {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        trust: PathBuf,
    },
    Cosign {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        password_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Args)]
struct ControllerArgs {
    #[command(subcommand)]
    command: ControllerCommand,
}

#[derive(Debug, Subcommand)]
enum ControllerCommand {
    Init {
        #[arg(long)]
        config: PathBuf,
    },
    Import {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
    Export {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        output: PathBuf,
    },
    Status {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        job_id: Option<String>,
    },
    AuditVerify {
        #[arg(long)]
        config: PathBuf,
    },
    Listen {
        #[arg(long)]
        config: PathBuf,
    },
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Debug, Args)]
struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    Once {
        #[arg(long)]
        config: PathBuf,
    },
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    Check {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Debug, Args)]
struct CertificateArgs {
    #[command(subcommand)]
    command: CertificateCommand,
}

#[derive(Debug, Subcommand)]
enum CertificateCommand {
    Fingerprint {
        #[arg(long)]
        certificate: PathBuf,
    },
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Identity(arguments) => identity_command(arguments.command),
        Command::Trust(arguments) => trust_command(arguments.command),
        Command::Job(arguments) => job_command(arguments.command),
        Command::Bundle(arguments) => bundle_command(arguments.command),
        Command::Controller(arguments) => controller_command(arguments.command),
        Command::Agent(arguments) => agent_command(arguments.command),
        Command::Certificate(arguments) => certificate_command(arguments.command),
        Command::Actions => {
            let actions: Vec<Value> = ACTIONS
                .iter()
                .map(|(action, risk)| json!({"action": action, "risk": risk}))
                .collect();
            print_json(&json!({"actions": actions}))
        }
    }
}

fn identity_command(command: IdentityCommand) -> Result<()> {
    match command {
        IdentityCommand::Generate {
            id,
            output,
            password_file,
        } => {
            let mut password = password(&password_file)?;
            let public = Identity::generate(&id, &output, &password);
            clear_password(&mut password);
            let public = public?;
            print_json(&json!({
                "identity_id": public.identity_id,
                "signing_key_id": public.signing.key_id,
                "encryption_key_id": public.encryption.key_id,
                "public_identity": Identity::public_path(&output),
            }))
        }
        IdentityCommand::Show { identity } => {
            let path = if identity.is_dir() {
                Identity::public_path(&identity)
            } else {
                identity
            };
            print_json(&serde_json::to_value(PublicIdentity::read(&path)?)?)
        }
    }
}

fn trust_command(command: TrustCommand) -> Result<()> {
    match command {
        TrustCommand::Init { store } => {
            if store.exists() {
                return Err(Error::InvalidInput(format!(
                    "trust store {} already exists",
                    store.display()
                )));
            }
            TrustStore::default().write(&store)?;
            print_json(&json!({"store": store, "trust_epoch": 1}))
        }
        TrustCommand::Add {
            store,
            public_identity,
            role,
            actions,
            max_risk,
        } => {
            let mut trust = TrustStore::read(&store)?;
            let identity = PublicIdentity::read(&public_identity)?;
            let identity_id = identity.identity_id.clone();
            let key_id = identity.signing.key_id.clone();
            trust.add(identity, role, actions, max_risk)?;
            trust.write(&store)?;
            print_json(&json!({
                "identity_id": identity_id, "key_id": key_id, "trust_epoch": trust.trust_epoch,
            }))
        }
        TrustCommand::Revoke { store, key_id } => {
            let mut trust = TrustStore::read(&store)?;
            trust.revoke(&key_id)?;
            trust.write(&store)?;
            print_json(&json!({"revoked": key_id, "trust_epoch": trust.trust_epoch}))
        }
        TrustCommand::List { store } => {
            let trust = TrustStore::read(&store)?;
            let entries: Vec<Value> = trust
                .entries
                .iter()
                .map(|(key_id, entry)| {
                    json!({
                        "identity_id": entry.identity.identity_id,
                        "key_id": key_id,
                        "role": entry.role,
                        "max_risk": entry.max_risk,
                        "actions": entry.allowed_actions,
                        "revoked": entry.revoked,
                    })
                })
                .collect();
            print_json(&json!({"trust_epoch": trust.trust_epoch, "entries": entries}))
        }
    }
}

#[allow(clippy::too_many_lines)]
fn job_command(command: JobCommand) -> Result<()> {
    match command {
        JobCommand::Create {
            identity,
            password_file,
            recipients,
            action,
            targets,
            params,
            attachments,
            job_id,
            sequence,
            expires_in,
            not_before,
            dry_run,
            output,
        } => {
            ensure_extension(&output, "hail")?;
            let sequence = sequence.unwrap_or(next_identity_sequence(&identity)?);
            let mut password = password(&password_file)?;
            let sender = Identity::load(&identity, &password);
            clear_password(&mut password);
            let sender = sender?;
            let recipients = recipients
                .iter()
                .map(|path| PublicIdentity::read(path))
                .collect::<Result<Vec<_>>>()?;
            let params = match params {
                Some(path) => {
                    match serde_json::from_slice::<Value>(&read_limited(&path, 4 * 1024 * 1024)?)? {
                        Value::Object(map) => map,
                        _ => {
                            return Err(Error::InvalidInput(
                                "job params must be a JSON object".into(),
                            ));
                        }
                    }
                }
                None => Map::new(),
            };
            let attachments = attachments
                .iter()
                .map(|specification| read_attachment(specification))
                .collect::<Result<Vec<_>>>()?;
            let created_at = now();
            let expires_at = created_at
                + Duration::seconds(
                    i64::try_from(parse_duration_seconds(&expires_in)?)
                        .map_err(|_| Error::InvalidInput("duration is too large".into()))?,
                );
            let not_before = not_before
                .map(|value| parse_timestamp(&value))
                .transpose()?;
            let job_id = job_id.unwrap_or_else(|| Uuid::new_v4().to_string());
            let job = Job {
                job_id: job_id.clone(),
                action,
                targets,
                params,
                attachments,
                dry_run,
                created_at,
                not_before,
                expires_at,
            };
            job.validate(32 * 1024 * 1024)?;
            let bundle = Bundle::seal(
                BundleKind::Hail,
                &job_id,
                &sender,
                &recipients,
                &job,
                sequence,
                created_at,
                not_before,
                expires_at,
            )?;
            bundle.write(&output)?;
            print_json(&json!({
                "job_id": job_id,
                "bundle_id": bundle.protected.bundle_id,
                "output": output,
                "signatures": bundle.signatures.len(),
            }))
        }
    }
}

fn bundle_command(command: BundleCommand) -> Result<()> {
    match command {
        BundleCommand::Inspect {
            input,
            identity,
            password_file,
            trust,
        } => {
            let bundle = Bundle::read(&input)?;
            let verification = trust
                .map(|path| {
                    let trust = TrustStore::read(&path)?;
                    Ok::<_, Error>(bundle.verify_signatures(&trust)?.len())
                })
                .transpose()?;
            let payload = match (identity, password_file) {
                (Some(identity), Some(password_file)) => {
                    let mut password = password(&password_file)?;
                    let identity = Identity::load(&identity, &password);
                    clear_password(&mut password);
                    Some(bundle.decrypt::<Value>(&identity?)?)
                }
                (None, None) => None,
                _ => {
                    return Err(Error::InvalidInput(
                        "identity and password-file are required together".into(),
                    ));
                }
            };
            print_json(&json!({
                "format": bundle.format,
                "version": bundle.version,
                "protected": bundle.protected,
                "signatures": bundle.signatures.iter().map(|signature| json!({
                    "identity_id": signature.identity_id, "key_id": signature.key_id,
                })).collect::<Vec<_>>(),
                "verified_signature_count": verification,
                "payload": payload,
            }))
        }
        BundleCommand::Verify { input, trust } => {
            let bundle = Bundle::read(&input)?;
            bundle.validate_time(now())?;
            let trust = TrustStore::read(&trust)?;
            let signers = bundle.verify_signatures(&trust)?;
            print_json(&json!({
                "valid": true,
                "bundle_id": bundle.protected.bundle_id,
                "signers": signers.iter().map(|entry| &entry.identity.identity_id).collect::<Vec<_>>(),
            }))
        }
        BundleCommand::Cosign {
            input,
            identity,
            password_file,
            output,
        } => {
            let mut bundle = Bundle::read(&input)?;
            ensure_extension(&output, bundle.kind().extension())?;
            bundle.validate_time(now())?;
            let mut password = password(&password_file)?;
            let signer = Identity::load(&identity, &password);
            clear_password(&mut password);
            let signer = signer?;
            let _: Value = bundle.decrypt(&signer)?;
            bundle.add_signature(&signer)?;
            bundle.write(&output)?;
            print_json(&json!({
                "bundle_id": bundle.protected.bundle_id,
                "output": output,
                "signatures": bundle.signatures.len(),
            }))
        }
    }
}

fn controller_command(command: ControllerCommand) -> Result<()> {
    match command {
        ControllerCommand::Init { config } => {
            let config = ControllerConfig::read(&config)?;
            Controller::initialize(&config)?;
            print_json(
                &json!({"initialized": true, "database": config.database, "outbox": config.outbox}),
            )
        }
        ControllerCommand::Import { config, input } => {
            ensure_extension(&input, "hail")?;
            let controller = load_controller(&config)?;
            let job_id = controller.import_hail(&Bundle::read(&input)?)?;
            print_json(&json!({"imported": true, "job_id": job_id}))
        }
        ControllerCommand::Export {
            config,
            job_id,
            output,
        } => {
            ensure_extension(&output, "mary")?;
            let bundle = load_controller(&config)?.export_mary(&job_id)?;
            bundle.write(&output)?;
            print_json(&json!({
                "job_id": job_id, "bundle_id": bundle.protected.bundle_id, "output": output,
            }))
        }
        ControllerCommand::Status { config, job_id } => {
            print_json(&load_controller(&config)?.status(job_id.as_deref())?)
        }
        ControllerCommand::AuditVerify { config } => {
            let count = load_controller(&config)?.verify_audit()?;
            print_json(&json!({"valid": true, "entries": count}))
        }
        ControllerCommand::Listen { config } => {
            let controller = Arc::new(load_controller(&config)?);
            println!("HailMary ingress listener active");
            hailmary::listener::Listener::new(controller)?.run()
        }
        ControllerCommand::Serve { config } => {
            let controller = load_controller(&config)?;
            println!(
                "HailMary controller listening on {}",
                controller.config.network.bind
            );
            hailmary::protocol::serve(controller)
        }
    }
}

fn agent_command(command: AgentCommand) -> Result<()> {
    match command {
        AgentCommand::Check { config } => {
            let config = AgentConfig::read(&config)?;
            hailmary::policy::AgentPolicy::read(&config.policy)?;
            print_json(&json!({"valid": true, "node_id": config.node_id}))
        }
        AgentCommand::Once { config } => {
            let outcome = Agent::load(AgentConfig::read(&config)?)?.cycle()?;
            print_json(&json!({"outcome": format!("{outcome:?}").to_lowercase()}))
        }
        AgentCommand::Run { config } => {
            let agent = Agent::load(AgentConfig::read(&config)?)?;
            loop {
                match agent.cycle() {
                    Ok(CycleOutcome::Idle) => {
                        thread::sleep(StdDuration::from_secs(agent.poll_seconds()));
                    }
                    Ok(CycleOutcome::ResultSubmitted) => {}
                    Err(error) => {
                        eprintln!("agent cycle failed: {error}");
                        thread::sleep(StdDuration::from_secs(agent.poll_seconds()));
                    }
                }
            }
        }
    }
}

fn certificate_command(command: CertificateCommand) -> Result<()> {
    match command {
        CertificateCommand::Fingerprint { certificate } => {
            let certificate = CertificateDer::pem_file_iter(&certificate)
                .map_err(|error| Error::Crypto(error.to_string()))?
                .next()
                .transpose()
                .map_err(|error| Error::Crypto(error.to_string()))?
                .ok_or_else(|| Error::InvalidInput("certificate file is empty".into()))?;
            print_json(&json!({"sha256": sha256_hex(certificate.as_ref())}))
        }
    }
}

fn load_controller(path: &Path) -> Result<Controller> {
    let config = ControllerConfig::read(path)?;
    let mut password = password(&config.identity_password_file)?;
    let controller = Controller::load(config, &password);
    clear_password(&mut password);
    controller
}

fn password(path: &Path) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(Error::PolicyDenied(format!(
                "password file {} must not be accessible by group or other users",
                path.display()
            )));
        }
    }
    let mut value = read_limited(path, 16 * 1024)?;
    while matches!(value.last(), Some(b'\n' | b'\r')) {
        value.pop();
    }
    if value.len() < 12 {
        return Err(Error::InvalidInput(
            "password file must contain at least 12 bytes".into(),
        ));
    }
    Ok(value)
}

fn read_attachment(specification: &str) -> Result<Attachment> {
    let (name, path) = specification
        .split_once('=')
        .ok_or_else(|| Error::InvalidInput("attachment must use NAME=PATH".into()))?;
    let path = PathBuf::from(path);
    let bytes = read_limited(&path, 32 * 1024 * 1024)?;
    Ok(Attachment::new(
        name.into(),
        "application/octet-stream".into(),
        &bytes,
    ))
}

fn ensure_extension(path: &Path, expected: &str) -> Result<()> {
    if path.extension().and_then(|value| value.to_str()) == Some(expected) {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "{} must use the .{expected} extension",
            path.display()
        )))
    }
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| Error::InvalidInput("timestamp must be RFC 3339".into()))
}

fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn next_identity_sequence(identity_directory: &Path) -> Result<u64> {
    let database = identity_directory.join("operator-state.db");
    let mut connection = Connection::open(database)?;
    connection.busy_timeout(StdDuration::from_secs(5))?;
    connection.execute(
        "CREATE TABLE IF NOT EXISTS sequence (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), value INTEGER NOT NULL)",
        [],
    )?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let current: Option<u64> = transaction
        .query_row(
            "SELECT value FROM sequence WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let next = current.unwrap_or(0).saturating_add(1);
    transaction.execute(
        "INSERT INTO sequence (singleton, value) VALUES (1, ?1)
         ON CONFLICT(singleton) DO UPDATE SET value = excluded.value",
        [next],
    )?;
    transaction.commit()?;
    Ok(next)
}
