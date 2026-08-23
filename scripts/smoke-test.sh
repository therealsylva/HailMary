#!/usr/bin/env bash
set -euo pipefail

binary=${1:-target/debug/hailmary}
binary=$(realpath "$binary")
project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work_directory=$(mktemp -d)
controller_pid=""

cleanup() {
  if [[ -n "$controller_pid" ]]; then
    kill "$controller_pid" 2>/dev/null || true
    wait "$controller_pid" 2>/dev/null || true
  fi
  rm -rf "$work_directory"
}
trap cleanup EXIT

mkdir -p "$work_directory/secrets" "$work_directory/state"
printf '%s' 'operator smoke test password' > "$work_directory/secrets/operator.password"
printf '%s' 'controller smoke test password' > "$work_directory/secrets/controller.password"
chmod 600 "$work_directory/secrets"/*.password

"$binary" identity generate \
  --id smoke-operator \
  --output "$work_directory/state/operator" \
  --password-file "$work_directory/secrets/operator.password" >/dev/null
"$binary" identity generate \
  --id smoke-controller \
  --output "$work_directory/state/controller" \
  --password-file "$work_directory/secrets/controller.password" >/dev/null

"$binary" trust init --store "$work_directory/state/controller-trust.json" >/dev/null
"$binary" trust add \
  --store "$work_directory/state/controller-trust.json" \
  --public "$work_directory/state/operator/identity.hmpub" \
  --role operator \
  --action '*' \
  --max-risk critical >/dev/null

"$project_root/scripts/generate-pki.sh" \
  "$work_directory/state/pki" localhost node-001 >/dev/null
fingerprint=$("$binary" certificate fingerprint \
  --certificate "$work_directory/state/pki/agents/node-001.crt" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')

cat > "$work_directory/controller.toml" <<EOF
version = 1
identity_directory = "state/controller"
identity_password_file = "secrets/controller.password"
trust_store = "state/controller-trust.json"
database = "state/controller.db"
outbox = "state/outbox"

[network]
bind = "127.0.0.1:$port"
tls_certificate = "state/pki/server.crt"
tls_private_key = "state/pki/server.key"
client_ca = "state/pki/ca.crt"
max_frame_bytes = 16777216
lease_seconds = 30

[approvals]
read_only = 1
reversible = 1
disruptive = 1
critical = 1

[nodes.node-001]
certificate_sha256 = "$fingerprint"
EOF

cat > "$work_directory/policy.toml" <<'EOF'
version = 1
allowed_actions = ["inventory.collect"]
max_read_bytes = 1048576
max_artifact_bytes = 1048576
max_output_bytes = 1048576
EOF

cat > "$work_directory/agent.toml" <<EOF
version = 1
node_id = "node-001"
policy = "policy.toml"
state_database = "state/agent.db"

[controller]
address = "127.0.0.1:$port"
server_name = "localhost"
ca_certificate = "state/pki/ca.crt"
client_certificate = "state/pki/agents/node-001.crt"
client_private_key = "state/pki/agents/node-001.key"
poll_seconds = 1
max_frame_bytes = 16777216
EOF

"$binary" controller init --config "$work_directory/controller.toml" >/dev/null
job_id=$("$binary" job create \
  --identity "$work_directory/state/operator" \
  --password-file "$work_directory/secrets/operator.password" \
  --recipient "$work_directory/state/controller/identity.hmpub" \
  --action inventory.collect \
  --target node-001 \
  --output "$work_directory/request.hail" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')
"$binary" controller import \
  --config "$work_directory/controller.toml" \
  --input "$work_directory/request.hail" >/dev/null

"$binary" controller serve --config "$work_directory/controller.toml" \
  >"$work_directory/controller.log" 2>&1 &
controller_pid=$!

completed=false
for _ in $(seq 1 60); do
  if "$binary" agent once --config "$work_directory/agent.toml" \
    >"$work_directory/agent.log" 2>&1; then
    completed=true
    break
  fi
  sleep 0.25
done
if [[ "$completed" != true ]]; then
  cat "$work_directory/controller.log" >&2
  cat "$work_directory/agent.log" >&2
  echo "agent could not complete smoke-test job" >&2
  exit 1
fi

"$binary" controller export \
  --config "$work_directory/controller.toml" \
  --job-id "$job_id" \
  --output "$work_directory/result.mary" >/dev/null
"$binary" trust init --store "$work_directory/state/operator-trust.json" >/dev/null
"$binary" trust add \
  --store "$work_directory/state/operator-trust.json" \
  --public "$work_directory/state/controller/identity.hmpub" \
  --role controller \
  --action '*' \
  --max-risk critical >/dev/null
"$binary" bundle inspect \
  --input "$work_directory/result.mary" \
  --identity "$work_directory/state/operator" \
  --password-file "$work_directory/secrets/operator.password" \
  --trust "$work_directory/state/operator-trust.json" |
  python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["payload"]["status"] == "succeeded"; assert data["verified_signature_count"] == 1'

echo "HailMary end-to-end smoke test passed"
