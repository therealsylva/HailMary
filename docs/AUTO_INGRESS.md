# Automatic ingress listener

The controller listener automates the existing `.hail` import step. It does not create a second
execution path and does not weaken signature, encryption, approval, action, target, time or replay
checks. A successfully imported job is immediately available for its target agent to claim through
the normal mTLS polling channel.

## Configuration

Add the optional listener table to `controller.toml`:

```toml
[listener]
enabled = true
inboxes = ["/var/lib/hailmary/inbox", "/media/hailmary"]
state_directory = "/var/lib/hailmary/ingress"
poll_seconds = 2
settle_seconds = 2
max_bundle_bytes = 67108864
```

- `inboxes` accepts multiple ordinary directories or mounted removable-media roots. Scanning is
  intentionally non-recursive.
- `state_directory` must be a trusted local filesystem writable only by the controller service.
  Do not place it on removable media.
- `poll_seconds` controls how often the listener checks for work.
- `settle_seconds` is the minimum time a candidate's size and modification time must remain stable.
- `max_bundle_bytes` cannot exceed HailMary's global 64 MiB bundle limit.

Relative paths are resolved from the controller configuration file. Missing inboxes are tolerated,
which allows a USB mount to appear and disappear while the controller stays active. Inbox paths
themselves must be real directories, not symbolic links.

## Running

`controller serve` automatically starts ingress when `listener.enabled` is true:

```bash
hailmary controller serve --config /etc/hailmary/controller.toml
```

For foreground listener-only operation:

```bash
hailmary controller listen --config /etc/hailmary/controller.toml
```

Run only one listener for a controller state directory. Normal production deployments should use
the listener embedded in `controller serve`.

## Processing states

The listener never renames, deletes or writes to a source inbox. This permits read-only mounted
media. Once a file is stable, its bytes are copied to the local state directory using an atomic
write and addressed by SHA-256:

| Directory | Meaning |
|---|---|
| `pending/` | Fully copied bundle awaiting or undergoing verification |
| `accepted/` | Bundle imported into the controller queue |
| `rejected/` | Bundle that permanently failed format, trust, policy, expiry or replay checks |
| `receipts/` | JSON outcome record keyed by the same SHA-256 digest |

A `not_before` bundle remains pending and is retried after it becomes valid. Transient local I/O or
database errors also leave the bundle pending. Permanent failures that fit inside the configured
limit are quarantined once and are not retried while identical content remains in any configured
inbox. Oversized, symbolic-link and other unreadable entries are reported but never copied out of
the source inbox.

If the process stops after database import but before archiving, startup recovery compares the exact
protected bundle with the queued envelope. An exact match is archived as already imported; altered
content with a colliding job or bundle identifier is rejected. This prevents a crash from creating
a second execution.

## USB and service hardening

- Mount inbound USB media with `nodev`, `nosuid`, `noexec` and preferably read-only options.
- Give the service account read access to inboxes, not ownership of the removable filesystem.
- Keep the listener state directory under the controller's existing encrypted, backed-up state.
- With the provided systemd unit, add site-specific `ReadOnlyPaths=` entries for each inbox or mount.
- Do not configure an inbox that also receives `.mary` output.
- Continue recording media custody and transfer-station checks; automatic import removes a manual
  command, not the cross-domain approval process.
