use chrono::Duration;
use hailmary::bundle::{Bundle, BundleKind};
use hailmary::config::{
    ApprovalConfig, ControllerConfig, ControllerNetworkConfig, ListenerConfig, NodeAuthorization,
};
use hailmary::controller::Controller;
use hailmary::identity::Identity;
use hailmary::listener::{Listener, ListenerEvent};
use hailmary::model::{Job, RiskLevel};
use hailmary::trust::{TrustRole, TrustStore};
use hailmary::util::now;
use serde_json::Map;
use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;

const PASSWORD: &[u8] = b"correct horse battery staple";

#[test]
#[allow(clippy::too_many_lines)]
fn listener_imports_stable_hail_and_recovers_idempotently() {
    let temporary = tempfile::tempdir().unwrap();
    let inbox = temporary.path().join("usb-inbox");
    let removable_inbox = temporary.path().join("removable-not-mounted");
    fs::create_dir(&inbox).unwrap();

    let operator_directory = temporary.path().join("operator");
    let controller_directory = temporary.path().join("controller");
    let operator_public = Identity::generate("operator-a", &operator_directory, PASSWORD).unwrap();
    let controller_public =
        Identity::generate("controller-a", &controller_directory, PASSWORD).unwrap();
    let operator = Identity::load(&operator_directory, PASSWORD).unwrap();

    let trust_path = temporary.path().join("trust.json");
    let mut trust = TrustStore::default();
    trust
        .add(
            operator_public,
            TrustRole::Operator,
            vec!["*".into()],
            RiskLevel::Critical,
        )
        .unwrap();
    trust.write(&trust_path).unwrap();

    let listener_state = temporary.path().join("listener-state");
    let config = ControllerConfig {
        version: 1,
        identity_directory: controller_directory,
        identity_password_file: temporary.path().join("password"),
        trust_store: trust_path,
        database: temporary.path().join("controller.db"),
        outbox: temporary.path().join("outbox"),
        network: ControllerNetworkConfig {
            bind: "127.0.0.1:0".into(),
            tls_certificate: temporary.path().join("server.crt"),
            tls_private_key: temporary.path().join("server.key"),
            client_ca: temporary.path().join("ca.crt"),
            max_frame_bytes: 1024 * 1024,
            lease_seconds: 60,
        },
        listener: Some(ListenerConfig {
            enabled: true,
            inboxes: vec![inbox.clone(), removable_inbox.clone()],
            state_directory: listener_state.clone(),
            poll_seconds: 1,
            settle_seconds: 0,
            max_bundle_bytes: 1024 * 1024,
        }),
        approvals: ApprovalConfig::default(),
        nodes: BTreeMap::from([(
            "node-1".into(),
            NodeAuthorization {
                certificate_sha256: "00".repeat(32),
            },
        )]),
    };
    let controller = Arc::new(Controller::load(config, PASSWORD).unwrap());

    let created = now();
    let job = Job {
        job_id: "listener-job-1".into(),
        action: "inventory.collect".into(),
        targets: vec!["node-1".into()],
        params: Map::new(),
        attachments: Vec::new(),
        dry_run: false,
        created_at: created,
        not_before: None,
        expires_at: created + Duration::hours(1),
    };
    let hail = Bundle::seal(
        BundleKind::Hail,
        &job.job_id,
        &operator,
        std::slice::from_ref(&controller_public),
        &job,
        1,
        created,
        None,
        job.expires_at,
    )
    .unwrap();
    let source = inbox.join("approved-task.hail");
    hail.write(&source).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&source, fs::Permissions::from_mode(0o444)).unwrap();
    }

    let mut listener = Listener::new(Arc::clone(&controller)).unwrap();
    let events = listener.scan_once().unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        ListenerEvent::InboxUnavailable { inbox, .. }
            if inbox.ends_with("removable-not-mounted")
    )));
    let (digest, archived) = events
        .iter()
        .find_map(|event| match event {
            ListenerEvent::Imported {
                sha256,
                archived,
                job_id,
                already_imported,
                ..
            } => {
                assert_eq!(job_id, "listener-job-1");
                assert!(!already_imported);
                Some((sha256.clone(), archived.clone()))
            }
            _ => None,
        })
        .expect("listener should import the bundle");
    assert!(
        source.exists(),
        "the listener must not alter removable media"
    );
    assert!(std::path::Path::new(&archived).exists());
    assert_eq!(
        controller.claim("node-1").unwrap().unwrap().job_id,
        "listener-job-1"
    );

    let accepted = listener_state
        .join("accepted")
        .join(format!("{digest}.hail"));
    let pending = listener_state
        .join("pending")
        .join(format!("{digest}.hail"));
    fs::rename(&accepted, &pending).unwrap();
    let mut restarted = Listener::new(Arc::clone(&controller)).unwrap();
    let recovered = restarted.scan_once().unwrap();
    assert!(recovered.iter().any(|event| matches!(
        event,
        ListenerEvent::Imported {
            job_id,
            already_imported: true,
            ..
        } if job_id == "listener-job-1"
    )));
    assert!(accepted.exists());

    fs::create_dir(&removable_inbox).unwrap();
    fs::write(
        removable_inbox.join("invalid.hail"),
        b"not a HailMary bundle",
    )
    .unwrap();
    let rejected = restarted.scan_once().unwrap();
    assert!(rejected.iter().any(|event| matches!(
        event,
        ListenerEvent::Rejected {
            quarantined: Some(_),
            sha256: Some(_),
            ..
        }
    )));
    assert_eq!(
        fs::read_dir(listener_state.join("receipts"))
            .unwrap()
            .count(),
        2
    );

    let future = now() + Duration::minutes(5);
    let deferred_job = Job {
        job_id: "listener-job-future".into(),
        action: "health.collect".into(),
        targets: vec!["node-1".into()],
        params: Map::new(),
        attachments: Vec::new(),
        dry_run: false,
        created_at: created,
        not_before: Some(future),
        expires_at: created + Duration::hours(1),
    };
    let deferred_hail = Bundle::seal(
        BundleKind::Hail,
        &deferred_job.job_id,
        &operator,
        &[controller_public],
        &deferred_job,
        2,
        created,
        Some(future),
        deferred_job.expires_at,
    )
    .unwrap();
    deferred_hail
        .write(&inbox.join("future-task.hail"))
        .unwrap();
    let deferred = restarted.scan_once().unwrap();
    assert!(deferred.iter().any(|event| matches!(
        event,
        ListenerEvent::Deferred { reason, .. } if reason.contains("not valid before")
    )));
    assert_eq!(
        fs::read_dir(listener_state.join("pending"))
            .unwrap()
            .count(),
        2
    );
}
