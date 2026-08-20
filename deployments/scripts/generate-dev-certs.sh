#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cert_dir="$repo_root/deployments/local/certs"
chain_dir="$repo_root/deployments/local/chain"
agent_dir="$repo_root/deployments/local/agent"
validator_dir="$repo_root/deployments/local/validators"
mkdir -p "$cert_dir"
mkdir -p "$chain_dir"
mkdir -p "$agent_dir"
mkdir -p "$repo_root/deployments/local/agent-2"
mkdir -p "$repo_root/deployments/local/agent-3"
mkdir -p "$validator_dir"
chmod 700 "$cert_dir"
chmod 755 "$chain_dir"
chmod 700 "$agent_dir"
chmod 700 "$repo_root/deployments/local/agent-2"
chmod 700 "$repo_root/deployments/local/agent-3"
chmod 700 "$validator_dir"

# Every provider-agent instance the Compose file can start (the default
# provider-agent plus the opt-in multi-node profile's provider-agent-2/
# provider-agent-3, deployments/docker-compose.yml) shares this one
# agent-server certificate rather than each getting its own: the Control
# Plane's outbound TLS verification sets ServerName to the dialed
# hostname (control-plane/internal/agentmanager/client.go), so the SAN
# list below must cover every hostname any Agent could be reached at,
# whether or not that instance's Compose profile is actually enabled --
# an unused extra SAN entry is harmless, unlike a missing one, which
# breaks that Agent's TLS handshake outright.
agent_server_san="subjectAltName=DNS:provider-agent,DNS:provider-agent-2,DNS:provider-agent-3,DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
"

if [[ ! -f "$cert_dir/bridge-key.pem" || ! -f "$cert_dir/bridge-public.hex" ]]; then
  openssl genpkey -algorithm ED25519 -out "$cert_dir/bridge-key.pem"
  openssl pkey -in "$cert_dir/bridge-key.pem" -pubout -outform DER \
    | tail -c 32 | xxd -p -c 64 > "$cert_dir/bridge-public.hex"
  chmod 600 "$cert_dir/bridge-key.pem"
  chmod 644 "$cert_dir/bridge-public.hex"
fi
cp "$cert_dir/bridge-public.hex" "$chain_dir/bridge-public.hex"
chmod 644 "$chain_dir/bridge-public.hex"

# Network Validator signing keys (ADR-011/013): one Ed25519 PKCS#8 key
# per validator instance the Compose file can start (the default
# networkvalidator plus the opt-in multi-node profile's
# networkvalidator-2/networkvalidator-3). Each key is a validator's one
# identity for everything it does -- signing its own chain extrinsics
# directly (never sudo-wrapped, never sharing the bridge account above)
# and, self-signed, its mTLS client certificate to a Provider Agent
# (control-plane/internal/blockchainbridge/networkvalidatortls.go: the
# Agent checks the raw public key against a heartbeat-pushed allowlist,
# not a CA chain, so no CSR/CA-signing step is needed here, unlike the
# TLS certificates below). Distinct from the bridge/sudo key and from
# each other, matching ADR-011 §2's validators-are-independent-of-the-
# bridge trust boundary. Generated unconditionally, like the bridge key
# above and unlike the TLS certificates below, so it survives whether or
# not this script's later "certificates already exist" short-circuit
# fires. deployments/scripts/bootstrap-network-validators.sh funds and
# registers whichever of these actually have a running networkvalidator*
# Compose service.
for validator in validator validator-2 validator-3; do
  key_file="$validator_dir/$validator-key.pem"
  public_file="$validator_dir/$validator-public.hex"
  if [[ ! -f "$key_file" || ! -f "$public_file" ]]; then
    openssl genpkey -algorithm ED25519 -out "$key_file"
    openssl pkey -in "$key_file" -pubout -outform DER \
      | tail -c 32 | xxd -p -c 64 > "$public_file"
    chmod 600 "$key_file"
    chmod 644 "$public_file"
  fi
done

if [[ -f "$cert_dir/ca.crt" && -f "$cert_dir/ca.key" && -f "$cert_dir/server.crt" && -f "$cert_dir/client.crt" && ! -f "$cert_dir/agent-server.crt" ]]; then
  openssl req -newkey rsa:3072 -sha256 -nodes \
    -subj "/CN=provider-agent" \
    -keyout "$cert_dir/agent-server.key" -out "$cert_dir/agent-server.csr"
  openssl x509 -req -sha256 -days 90 \
    -in "$cert_dir/agent-server.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" \
    -CAcreateserial -out "$cert_dir/agent-server.crt" \
    -extfile <(printf '%s' "$agent_server_san")
  chmod 600 "$cert_dir/agent-server.key"
  rm -f "$cert_dir/agent-server.csr" "$cert_dir"/*.srl
fi

if [[ -f "$cert_dir/ca.crt" && -f "$cert_dir/server.crt" && -f "$cert_dir/client.crt" && -f "$cert_dir/agent-server.crt" ]]; then
  echo "Development certificates and blockchain bridge identity exist in $cert_dir"
  exit 0
fi

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -subj "/CN=OpenInfra Development CA" \
  -keyout "$cert_dir/ca.key" -out "$cert_dir/ca.crt"

openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj "/CN=control-plane" \
  -keyout "$cert_dir/server.key" -out "$cert_dir/server.csr"
openssl x509 -req -sha256 -days 90 \
  -in "$cert_dir/server.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" \
  -CAcreateserial -out "$cert_dir/server.crt" \
  -extfile <(printf 'subjectAltName=DNS:control-plane,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')

openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj "/CN=provider-agent-dev" \
  -keyout "$cert_dir/client.key" -out "$cert_dir/client.csr"
openssl x509 -req -sha256 -days 90 \
  -in "$cert_dir/client.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" \
  -CAcreateserial -out "$cert_dir/client.crt" \
  -extfile <(printf 'extendedKeyUsage=clientAuth\n')

openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj "/CN=provider-agent" \
  -keyout "$cert_dir/agent-server.key" -out "$cert_dir/agent-server.csr"
openssl x509 -req -sha256 -days 90 \
  -in "$cert_dir/agent-server.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" \
  -CAcreateserial -out "$cert_dir/agent-server.crt" \
  -extfile <(printf '%s' "$agent_server_san")

chmod 600 "$cert_dir"/*.key
rm -f "$cert_dir"/*.csr "$cert_dir"/*.srl
echo "Generated development mTLS certificates in $cert_dir"
