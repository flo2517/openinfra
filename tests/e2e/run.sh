#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
compose=(docker compose --env-file "$repo_root/.env" -f "$repo_root/deployments/docker-compose.yml")
test_dir="$(mktemp -d)"
provider_id=""

cleanup() {
  if [[ -n "$provider_id" ]]; then
    "${compose[@]}" exec -T redis redis-cli DEL "openinfra:heartbeat:$provider_id" >/dev/null || true
    "${compose[@]}" exec -T postgres sh -c \
      "psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -v ON_ERROR_STOP=1 -c \"DELETE FROM provider_chain_registrations WHERE provider_id='$provider_id'; DELETE FROM provider_join_completions WHERE provider_id='$provider_id'; DELETE FROM provider_join_challenges WHERE provider_id='$provider_id'; DELETE FROM providers WHERE provider_id='$provider_id';\"" >/dev/null || true
  fi
  rm -rf "$test_dir"
}
trap cleanup EXIT

"${compose[@]}" ps --status running --services | grep -qx control-plane
cargo build --quiet --manifest-path "$repo_root/provider-agent/Cargo.toml" -p agent-cli
agent="$repo_root/provider-agent/target/debug/agent-cli"

cd "$test_dir"
"$agent" init >/dev/null
export TLS_CERT_FILE="$repo_root/deployments/local/certs/client.crt"
export TLS_KEY_FILE="$repo_root/deployments/local/certs/client.key"
export TLS_CA_FILE="$repo_root/deployments/local/certs/ca.crt"
export TLS_SERVER_NAME=control-plane

join_output="$(timeout 20s "$agent" join)"
provider_id="$(sed -n 's/^Provider ACTIVE: //p' <<<"$join_output")"
[[ "$provider_id" =~ ^[0-9a-f]{64}$ ]]

heartbeat_output="$(timeout 20s "$agent" heartbeat)"
grep -q "Provider ACTIVE: $provider_id (heartbeat 1)" <<<"$heartbeat_output"
[[ "$("${compose[@]}" exec -T redis redis-cli HGET "openinfra:heartbeat:$provider_id" sequence | tr -d '\r')" == "1" ]]
ttl="$("${compose[@]}" exec -T redis redis-cli PTTL "openinfra:heartbeat:$provider_id" | tr -d '\r')"
(( ttl > 0 ))

echo "E2E Provider Join + Heartbeat passed for $provider_id"
