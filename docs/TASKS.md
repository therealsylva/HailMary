# Task reference

Jobs accept a JSON object through `--params`. Attached files use `--attachment NAME=PATH` and are encrypted inside `.hail`.

## Read-only actions

### `inventory.collect`

No parameters. Returns host, operating-system, CPU, memory and disk information.

### `health.collect`

No parameters. Returns uptime, load, memory, process count and aggregate disk capacity.

### `logs.collect`

```json
{"source":"system","max_bytes":262144}
```

`source` must exist in `policy.log_sources`. Reads are limited by both the request and `max_read_bytes`; configured regular expressions redact output.

### `integrity.verify`

```json
{
  "root":"etc",
  "files":{"ssh/sshd_config":"EXPECTED_SHA256"}
}
```

Every file is resolved below a named canonical root. Absolute paths, parent traversal and symlink escapes are rejected.

### `service.status`

```json
{"name":"sshd"}
```

The service must be in `allowed_services`.

### `config.audit` and `file.retrieve`

```json
{"target":"sshd_config"}
```

The target must exist in `file_targets`. `file.retrieve` includes a bounded artifact in `.mary`.

## Mutating actions

### `service.restart`

Uses the same parameters and allowlist as `service.status`. `--dry-run` performs no mutation.

### `file.deploy`

```json
{
  "target":"application_config",
  "attachment":"configuration",
  "expected_sha256":"EXPECTED_SHA256"
}
```

Writes atomically to the exact path associated with `target`. Symlink targets are rejected. The optional configured mode is applied after replacement.

### `config.apply`

Uses the same parameters as `file.deploy`. If the target names a validator command profile, HailMary runs it without a shell. Failure restores the previous bytes and reports a failed result with `rollback_performed=true`.

### `package.install`

```json
{"profile":"debian_package","attachment":"package"}
```

The signed attachment is written to the configured staging directory. The named installer profile may contain `{artifact}` in its fixed argument list. The staged artifact is removed after execution.

### `patch.apply`

```json
{"profile":"security_updates"}
```

Runs a fixed local patch profile. Jobs cannot add or alter arguments.

### `backup.create`

```json
{"source":"application"}
```

Creates a gzip-compressed tar archive from a named source without following symlinks. The result must remain below `max_artifact_bytes`.

### `system.reboot`

No parameters. Runs only when `system.reboot` is allowlisted, a local `reboot_profile` exists and the controller has received the configured critical-action signature threshold.

## Command profiles

Command profiles are local policy, not job input:

```toml
[patch_profiles.security_updates]
program = "/usr/bin/dnf"
args = ["upgrade", "--security", "-y"]
timeout_seconds = 1800
```

HailMary invokes the program directly and never uses a shell. Standard input is closed. Standard output and error are bounded and redacted. A timeout kills the child process.
