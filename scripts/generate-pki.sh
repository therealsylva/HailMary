#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 OUTPUT_DIRECTORY SERVER_DNS_NAME NODE_ID [NODE_ID ...]" >&2
  exit 2
}

[[ $# -ge 3 ]] || usage

output_directory=$1
server_name=$2
shift 2

if [[ -e "$output_directory" ]]; then
  echo "refusing to overwrite existing path: $output_directory" >&2
  exit 1
fi

umask 077
mkdir -p "$output_directory/agents"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$output_directory/ca.key"
openssl req -x509 -new -sha256 -days 3650 \
  -key "$output_directory/ca.key" \
  -subj "/CN=HailMary Internal CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$output_directory/ca.crt"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$output_directory/server.key"
openssl req -new -sha256 \
  -key "$output_directory/server.key" \
  -subj "/CN=$server_name" \
  -out "$output_directory/server.csr"

server_extensions=$(mktemp)
trap 'rm -f "$server_extensions" "${agent_extensions:-}"' EXIT
printf '%s\n' \
  "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature,keyAgreement" \
  "extendedKeyUsage=serverAuth" \
  "subjectAltName=DNS:$server_name" > "$server_extensions"
openssl x509 -req -sha256 -days 825 \
  -in "$output_directory/server.csr" \
  -CA "$output_directory/ca.crt" \
  -CAkey "$output_directory/ca.key" \
  -CAcreateserial \
  -extfile "$server_extensions" \
  -out "$output_directory/server.crt"
rm -f "$output_directory/server.csr"

agent_extensions=$(mktemp)
printf '%s\n' \
  "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature,keyAgreement" \
  "extendedKeyUsage=clientAuth" > "$agent_extensions"

for node_id in "$@"; do
  if [[ ! "$node_id" =~ ^[A-Za-z0-9._:-]+$ ]]; then
    echo "invalid node ID: $node_id" >&2
    exit 1
  fi
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$output_directory/agents/$node_id.key"
  openssl req -new -sha256 \
    -key "$output_directory/agents/$node_id.key" \
    -subj "/CN=$node_id" \
    -out "$output_directory/agents/$node_id.csr"
  openssl x509 -req -sha256 -days 825 \
    -in "$output_directory/agents/$node_id.csr" \
    -CA "$output_directory/ca.crt" \
    -CAkey "$output_directory/ca.key" \
    -CAcreateserial \
    -extfile "$agent_extensions" \
    -out "$output_directory/agents/$node_id.crt"
  rm -f "$output_directory/agents/$node_id.csr"
done

chmod 600 "$output_directory"/*.key "$output_directory/agents"/*.key
chmod 644 "$output_directory"/*.crt "$output_directory/agents"/*.crt

echo "PKI created in $output_directory"
echo "Keep ca.key offline after enrollment."
