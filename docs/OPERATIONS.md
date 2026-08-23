# Operations guide

## Media workflow

1. Create and review a `.hail` on the operator console.
2. Record its filename, SHA-256, custodian, source station and destination.
3. Copy it to a dedicated inbound device.
4. Process the device through the ingress transfer station.
5. Import the bundle into the controller. A rejected import changes no replay state.
6. After completion, export `.mary` to the egress staging area.
7. Use a dedicated outbound device and the egress transfer station.
8. Verify and decrypt `.mary` at the operator console.
9. Sanitize or destroy media according to site policy.

Do not reuse one drive for both directions. Do not plug protected-network media into an internet-facing workstation.

When automatic ingress is enabled, steps 4 and 5 are performed by the controller listener. The
source file remains on the removable device; remove the device only after an `imported` event and
receipt are recorded. See [AUTO_INGRESS.md](AUTO_INGRESS.md).

## Two-person approval

Add both the controller and reviewer as encryption recipients when creating the job:

```bash
hailmary job create \
  --identity state/operator-alice \
  --password-file secrets/alice.password \
  --recipient state/controller/identity.hmpub \
  --recipient state/operator-bob/identity.hmpub \
  --action patch.apply \
  --target node-001 \
  --params patch.json \
  --output transfer/update.hail
```

The reviewer decrypts the exact payload before signing:

```bash
hailmary bundle inspect \
  --input transfer/update.hail \
  --identity state/operator-bob \
  --password-file secrets/bob.password

hailmary bundle cosign \
  --input transfer/update.hail \
  --identity state/operator-bob \
  --password-file secrets/bob.password \
  --output transfer/update-approved.hail
```

The controller counts distinct trusted operator identities whose action and risk permissions match.

## Enrollment

- Exchange `.hmpub` files through a witnessed setup ceremony.
- Compare signing and encryption key fingerprints over an independent channel.
- Add operator public identities to the controller trust store.
- Add the controller public identity to each operator trust store.
- Generate a private internal TLS CA.
- Enroll each node's exact leaf-certificate fingerprint in `controller.toml`.
- Protect password files, TLS private keys, databases and identities with operating-system permissions and full-disk encryption.

## Service deployment

Example systemd units are under `packaging/systemd`. Copy the release binary to `/usr/local/bin/hailmary`, configurations to `/etc/hailmary`, identities and trust stores to `/var/lib/hailmary`, then adjust ownership and `ReadWritePaths` for the local task policy.

The provided units intentionally apply hardening. Some task profiles need additional filesystem or kernel permissions; grant only the exact capability required instead of disabling all hardening. For automatic ingress, grant the controller service read-only access to each mount point and read-write access only to the configured local listener state directory.

## Backup and recovery

Back up the following through an approved protected process:

- Identity directories and encrypted `.hmk` files
- Password material or hardware-key recovery material
- Trust stores and current trust epoch
- Controller database and its WAL/SHM files as one consistent SQLite backup
- Agent execution journals
- TLS CA and enrollment records

Restoring an old controller database can also restore an old replay counter. After recovery, advance or rotate operator identities before accepting new bundles.

## Audit checks

```bash
hailmary controller audit-verify --config controller.toml
```

Periodically export the latest audit entry hash to a separately protected record. This makes tail deletion detectable.
