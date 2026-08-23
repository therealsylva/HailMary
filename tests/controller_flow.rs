use chrono::Duration;
use hailmary::bundle::{Bundle, BundleKind};
use hailmary::config::{
    ApprovalConfig, ControllerConfig, ControllerNetworkConfig, NodeAuthorization,
};
use hailmary::controller::Controller;
use hailmary::identity::Identity;
use hailmary::model::{ExecutionStatus, Job, MaryResult, NodeResult, RiskLevel};
use hailmary::trust::{TrustRole, TrustStore};
use hailmary::util::now;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

const PASSWORD: &[u8] = b"correct horse battery staple";

#[test]
#[allow(clippy::too_many_lines)]
fn hail_to_mary_controller_flow_is_replay_safe_and_audited() {
    let temporary = tempfile::tempdir().unwrap();
    let operator_dir = temporary.path().join("operator");
    let controller_dir = temporary.path().join("controller");
    let operator_public = Identity::generate("operator-a", &operator_dir, PASSWORD).unwrap();
    let controller_public = Identity::generate("controller-a", &controller_dir, PASSWORD).unwrap();
    let operator = Identity::load(&operator_dir, PASSWORD).unwrap();

    let trust_path = temporary.path().join("trust.json");
    let mut controller_trust = TrustStore::default();
    controller_trust
        .add(
            operator_public.clone(),
            TrustRole::Operator,
            vec!["*".into()],
            RiskLevel::Critical,
        )
        .unwrap();
    controller_trust.write(&trust_path).unwrap();

    let config = ControllerConfig {
        version: 1,
        identity_directory: controller_dir,
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
        listener: None,
        approvals: ApprovalConfig {
            read_only: 1,
            reversible: 1,
            disruptive: 2,
            critical: 2,
        },
        nodes: BTreeMap::from([(
            "node-1".into(),
            NodeAuthorization {
                certificate_sha256: "00".repeat(32),
            },
        )]),
    };
    let controller = Controller::load(config, PASSWORD).unwrap();
    let created = now();
    let job = Job {
        job_id: "job-1".into(),
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
    assert_eq!(controller.import_hail(&hail).unwrap(), "job-1");
    assert!(controller.import_hail(&hail).is_err());

    let disruptive = Job {
        job_id: "job-needs-two-signers".into(),
        action: "patch.apply".into(),
        targets: vec!["node-1".into()],
        params: Map::from_iter([("profile".into(), Value::String("security".into()))]),
        attachments: Vec::new(),
        dry_run: true,
        created_at: created,
        not_before: None,
        expires_at: created + Duration::hours(1),
    };
    let insufficiently_approved = Bundle::seal(
        BundleKind::Hail,
        &disruptive.job_id,
        &operator,
        std::slice::from_ref(&controller_public),
        &disruptive,
        2,
        created,
        None,
        disruptive.expires_at,
    )
    .unwrap();
    assert!(controller.import_hail(&insufficiently_approved).is_err());

    let claimed = controller.claim("node-1").unwrap().unwrap();
    assert_eq!(claimed.job_id, job.job_id);
    let result = NodeResult {
        job_id: job.job_id.clone(),
        node_id: "node-1".into(),
        action: job.action.clone(),
        status: ExecutionStatus::Succeeded,
        started_at: now(),
        completed_at: now(),
        summary: "inventory collected".into(),
        output: Value::Null,
        artifacts: Vec::new(),
        rollback_performed: false,
    };
    controller.complete("node-1", &result).unwrap();
    controller.complete("node-1", &result).unwrap();
    let mary = controller.export_mary("job-1").unwrap();
    let decoded: MaryResult = mary.decrypt(&operator).unwrap();
    assert_eq!(decoded.job_id, "job-1");
    assert_eq!(decoded.results.len(), 1);

    let mut operator_trust = TrustStore::default();
    operator_trust
        .add(
            controller_public,
            TrustRole::Controller,
            vec!["*".into()],
            RiskLevel::Critical,
        )
        .unwrap();
    assert_eq!(mary.verify_signatures(&operator_trust).unwrap().len(), 1);
    assert!(controller.verify_audit().unwrap() >= 4);
}
