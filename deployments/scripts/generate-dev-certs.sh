#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cert_dir="$repo_root/deployments/local/certs"
chain_dir="$repo_root/deployments/local/chain"
mkdir -p "$cert_dir"
mkdir -p "$chain_dir"
chmod 700 "$cert_dir"
chmod 755 "$chain_dir"

if [[ ! -f "$cert_dir/bridge-key.pem" || ! -f "$cert_dir/bridge-public.hex" ]]; then
  openssl genpkey -algorithm ED25519 -out "$cert_dir/bridge-key.pem"
  openssl pkey -in "$cert_dir/bridge-key.pem" -pubout -outform DER \
    | tail -c 32 | xxd -p -c 64 > "$cert_dir/bridge-public.hex"
  chmod 600 "$cert_dir/bridge-key.pem"
  chmod 644 "$cert_dir/bridge-public.hex"
fi
cp "$cert_dir/bridge-public.hex" "$chain_dir/bridge-public.hex"
chmod 644 "$chain_dir/bridge-public.hex"

if [[ -f "$cert_dir/ca.crt" && -f "$cert_dir/ca.key" && -f "$cert_dir/server.crt" && -f "$cert_dir/client.crt" && ! -f "$cert_dir/agent-server.crt" ]]; then
  openssl req -newkey rsa:3072 -sha256 -nodes \
    -subj "/CN=provider-agent" \
    -keyout "$cert_dir/agent-server.key" -out "$cert_dir/agent-server.csr"
  openssl x509 -req -sha256 -days 90 \
    -in "$cert_dir/agent-server.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" \
    -CAcreateserial -out "$cert_dir/agent-server.crt" \
    -extfile <(printf 'subjectAltName=DNS:provider-agent,DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
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
  -extfile <(printf 'subjectAltName=DNS:provider-agent,DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')

chmod 600 "$cert_dir"/*.key
rm -f "$cert_dir"/*.csr "$cert_dir"/*.srl
echo "Generated development mTLS certificates in $cert_dir"
