use chrono::Duration;
use hailmary::bundle::{Bundle, BundleKind};
use hailmary::identity::Identity;
use hailmary::model::RiskLevel;
use hailmary::trust::{TrustRole, TrustStore};
use hailmary::util::now;
use serde_json::{Value, json};

const PASSWORD: &[u8] = b"correct horse battery staple";

#[test]
fn encrypted_bundle_round_trips_and_verifies() {
    let temporary = tempfile::tempdir().unwrap();
    let sender_dir = temporary.path().join("sender");
    let recipient_dir = temporary.path().join("recipient");
    let sender_public = Identity::generate("operator-a", &sender_dir, PASSWORD).unwrap();
    let recipient_public = Identity::generate("controller-a", &recipient_dir, PASSWORD).unwrap();
    let sender = Identity::load(&sender_dir, PASSWORD).unwrap();
    let recipient = Identity::load(&recipient_dir, PASSWORD).unwrap();
    let created = now();
    let payload = json!({"action": "inventory.collect", "targets": ["node-1"]});
    let bundle = Bundle::seal(
        BundleKind::Hail,
        "job-1",
        &sender,
        &[recipient_public],
        &payload,
        1,
        created,
        None,
        created + Duration::hours(1),
    )
    .unwrap();

    let mut trust = TrustStore::default();
    trust
        .add(
            sender_public,
            TrustRole::Operator,
            vec!["*".into()],
            RiskLevel::Critical,
        )
        .unwrap();
    assert_eq!(bundle.verify_signatures(&trust).unwrap().len(), 1);
    assert_eq!(bundle.decrypt::<Value>(&recipient).unwrap(), payload);
    assert!(bundle.validate_time(created + Duration::hours(2)).is_err());
}

#[test]
fn tampering_is_detected_before_decryption() {
    let temporary = tempfile::tempdir().unwrap();
    let sender_dir = temporary.path().join("sender");
    let recipient_dir = temporary.path().join("recipient");
    let sender_public = Identity::generate("operator-a", &sender_dir, PASSWORD).unwrap();
    let recipient_public = Identity::generate("controller-a", &recipient_dir, PASSWORD).unwrap();
    let sender = Identity::load(&sender_dir, PASSWORD).unwrap();
    let created = now();
    let mut bundle = Bundle::seal(
        BundleKind::Hail,
        "job-1",
        &sender,
        &[recipient_public],
        &json!({"safe": true}),
        1,
        created,
        None,
        created + Duration::hours(1),
    )
    .unwrap();
    let replacement = if bundle.ciphertext.ends_with('A') {
        'B'
    } else {
        'A'
    };
    bundle.ciphertext.pop();
    bundle.ciphertext.push(replacement);
    let mut trust = TrustStore::default();
    trust
        .add(
            sender_public,
            TrustRole::Operator,
            vec!["*".into()],
            RiskLevel::Critical,
        )
        .unwrap();
    assert!(bundle.verify_signatures(&trust).is_err());
}

#[test]
fn reviewer_can_decrypt_and_cosign_multi_recipient_bundle() {
    let temporary = tempfile::tempdir().unwrap();
    let sender_dir = temporary.path().join("sender");
    let reviewer_dir = temporary.path().join("reviewer");
    let controller_dir = temporary.path().join("controller");
    let sender_public = Identity::generate("operator-a", &sender_dir, PASSWORD).unwrap();
    let reviewer_public = Identity::generate("operator-b", &reviewer_dir, PASSWORD).unwrap();
    let controller_public = Identity::generate("controller-a", &controller_dir, PASSWORD).unwrap();
    let sender = Identity::load(&sender_dir, PASSWORD).unwrap();
    let reviewer = Identity::load(&reviewer_dir, PASSWORD).unwrap();
    let created = now();
    let payload = json!({"action": "system.reboot"});
    let mut bundle = Bundle::seal(
        BundleKind::Hail,
        "job-critical",
        &sender,
        &[controller_public, reviewer_public.clone()],
        &payload,
        9,
        created,
        None,
        created + Duration::hours(1),
    )
    .unwrap();
    assert_eq!(bundle.decrypt::<Value>(&reviewer).unwrap(), payload);
    bundle.add_signature(&reviewer).unwrap();

    let mut trust = TrustStore::default();
    for public in [sender_public, reviewer_public] {
        trust
            .add(
                public,
                TrustRole::Operator,
                vec!["system.reboot".into()],
                RiskLevel::Critical,
            )
            .unwrap();
    }
    assert_eq!(bundle.verify_signatures(&trust).unwrap().len(), 2);
}

#[test]
fn incorrect_private_key_password_is_rejected() {
    let temporary = tempfile::tempdir().unwrap();
    let identity_dir = temporary.path().join("identity");
    Identity::generate("operator-a", &identity_dir, PASSWORD).unwrap();
    assert!(Identity::load(&identity_dir, b"this password is incorrect").is_err());
}
