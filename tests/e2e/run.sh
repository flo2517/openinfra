#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
compose=(docker compose --env-file "$repo_root/.env" -f "$repo_root/deployments/docker-compose.yml")
# DATABASE_URL (for controlplane-admin, below) and the rest of the documented
# host-side dev env; TLS_*/CONTROL_PLANE_GRPC_ADDR are re-exported explicitly
# further down and take precedence over whatever this sets.
set -a
. "$repo_root/.env"
set +a
test_dir="$(mktemp -d)"
provider_id=""

# State for the SubmitWorkload -> Deploy -> RUNNING proof (issue #117),
# populated as that section below progresses. deploy_agent_dir runs a full
# `agent-cli start` daemon (unlike provider_id above, which only ever runs
# one-shot join/heartbeat) so it has a live mTLS gRPC server the Control
# Plane's orchestrator can actually dispatch a Deploy to.
deploy_agent_dir=""
deploy_agent_pid=""
deploy_provider_id=""
deploy_workload_id=""
deploy_container_id=""
deploy_user_id=""
deploy_api_key=""
workloadctl_bin=""

cleanup() {
  if [[ -n "$deploy_workload_id" && -n "$deploy_api_key" ]]; then
    OPENINFRA_API_KEY="$deploy_api_key" "$workloadctl_bin" stop "$deploy_workload_id" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      state="$(OPENINFRA_API_KEY="$deploy_api_key" "$workloadctl_bin" get "$deploy_workload_id" 2>/dev/null | sed -n 's/^state: //p')"
      [[ "$state" == "WORKLOAD_STATE_STOPPED" || "$state" == "WORKLOAD_STATE_FAILED" ]] && break
      sleep 3
    done
  fi
  if [[ -n "$deploy_agent_pid" ]]; then
    kill "$deploy_agent_pid" >/dev/null 2>&1 || true
    wait "$deploy_agent_pid" 2>/dev/null || true
  fi
  if [[ -n "$deploy_container_id" ]]; then
    docker rm -f "$deploy_container_id" >/dev/null 2>&1 || true
  fi
  if [[ -n "$deploy_workload_id" ]]; then
    "${compose[@]}" exec -T postgres sh -c \
      "psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -v ON_ERROR_STOP=1 -c \"DELETE FROM workloads WHERE workload_id='$deploy_workload_id';\"" >/dev/null || true
  fi
  if [[ -n "$deploy_provider_id" ]]; then
    "${compose[@]}" exec -T redis redis-cli DEL "openinfra:heartbeat:$deploy_provider_id" >/dev/null || true
    "${compose[@]}" exec -T postgres sh -c \
      "psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -v ON_ERROR_STOP=1 -c \"DELETE FROM provider_chain_registrations WHERE provider_id='$deploy_provider_id'; DELETE FROM provider_join_completions WHERE provider_id='$deploy_provider_id'; DELETE FROM provider_join_challenges WHERE provider_id='$deploy_provider_id'; DELETE FROM providers WHERE provider_id='$deploy_provider_id';\"" >/dev/null || true
  fi
  if [[ -n "$deploy_user_id" ]]; then
    "${compose[@]}" exec -T postgres sh -c \
      "psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -v ON_ERROR_STOP=1 -c \"DELETE FROM api_keys WHERE user_id='$deploy_user_id'; DELETE FROM users WHERE user_id='$deploy_user_id';\"" >/dev/null || true
  fi
  if [[ -n "$deploy_agent_dir" ]]; then
    rm -rf "$deploy_agent_dir"
  fi
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
# workloadctl (issue #116) and controlplane-admin are built once up front,
# same spirit as agent-cli above: proven-from-source tooling, not a
# pre-built binary the test trusts blindly.
workloadctl_bin="$test_dir/workloadctl"
controlplane_admin_bin="$test_dir/controlplane-admin"
go build -C "$repo_root/control-plane" -o "$workloadctl_bin" ./cmd/workloadctl
go build -C "$repo_root/control-plane" -o "$controlplane_admin_bin" ./cmd/controlplane-admin

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

# ADR-016 slice 6 (issue #76): dashboard RBAC and tenant isolation,
# driven against this same running stack through the real mTLS gRPC API
# and the real dashboard HTTP API. Build-tagged `e2e` so it stays out of
# `go test ./...`; see control-plane/internal/dashboard/e2e_rbac_test.go
# for why these scenarios cannot be covered by that package's unit tests.
cd "$repo_root/control-plane"
E2E_DASHBOARD_URL="${E2E_DASHBOARD_URL:-http://127.0.0.1:8080}" \
E2E_GRPC_ADDR="${CONTROL_PLANE_GRPC_ADDR:-127.0.0.1:50051}" \
E2E_COMPOSE="${compose[*]}" \
  go test -tags e2e -count=1 -timeout 10m -run 'TestE2E' ./internal/dashboard/

echo "E2E Dashboard RBAC + tenant isolation passed"

# --- SubmitWorkload -> Deploy -> RUNNING container proof (issue #117) ---
# SubmitWorkload/GetWorkload/StopWorkload are authenticated (ADR-016 slice
# 1, issue #92 -- postdates issue #116's "not yet authenticated" note), so
# this needs its own tenant + API key, minted the same offline way an
# operator would (cmd/controlplane-admin, issue #12).
create_user_output="$("$controlplane_admin_bin" create-user "e2e-workload-proof")"
deploy_user_id="$(sed -n 's/^user_id: //p' <<<"$create_user_output")"
deploy_api_key="$(sed -n 's/^api_key: //p' <<<"$create_user_output" | awk '{print $1}')"
[[ "$deploy_user_id" =~ ^[0-9a-f-]{36}$ ]]
[[ "$deploy_api_key" =~ ^oiu_[0-9a-f]{64}$ ]]

# A small, well-known image pinned by digest (validateSubmission requires
# it -- see internal/workloadapi/service.go). registry.k8s.io/pause, not
# alpine/nginx: the Agent's executor runs every container with
# cap_drop=ALL + no-new-privileges (agent-executor's BollardEngine::create),
# and both alpine's default shell (needs a tty/stdin, exits immediately)
# and nginx (needs CAP_CHOWN for /var/cache/nginx at startup) fail under
# that -- pause's entire job is to sit idle forever with zero privileges,
# which is exactly what this proof needs and nothing DeployRequest can
# override (the wire protocol carries no command/entrypoint field).
deploy_image="registry.k8s.io/pause:3.9"
docker pull -q "$deploy_image" >/dev/null
deploy_image_ref="$(docker inspect --format='{{index .RepoDigests 0}}' "$deploy_image")"

# A second, independent provider identity that runs the full `agent-cli
# start` daemon (background heartbeat loop + a live mTLS gRPC server for
# Deploy/Stop), unlike provider_id above which only ever proved one-shot
# join/heartbeat. advertised_endpoint uses host.docker.internal because
# the Control Plane container reaches this host-run Agent through the
# extra_hosts entry docker-compose.yml already sets up for exactly this.
deploy_agent_dir="$(mktemp -d)"
cd "$deploy_agent_dir"
"$agent" init >/dev/null
sed -i 's/^  listen_address: .*/  listen_address: 0.0.0.0:50098/' config.yaml
sed -i "s#^  advertised_endpoint: ''#  advertised_endpoint: https://host.docker.internal:50098#" config.yaml

deploy_join_output="$(timeout 20s "$agent" join)"
deploy_provider_id="$(sed -n 's/^Provider ACTIVE: //p' <<<"$deploy_join_output")"
[[ "$deploy_provider_id" =~ ^[0-9a-f]{64}$ ]]

export AGENT_TLS_CERT_FILE="$repo_root/deployments/local/certs/agent-server.crt"
export AGENT_TLS_KEY_FILE="$repo_root/deployments/local/certs/agent-server.key"
export AGENT_TLS_CLIENT_CA_FILE="$repo_root/deployments/local/certs/ca.crt"
("$agent" start >"$deploy_agent_dir/start.log" 2>&1) &
deploy_agent_pid=$!

heartbeat_ready=""
for _ in $(seq 1 15); do
  ttl="$("${compose[@]}" exec -T redis redis-cli PTTL "openinfra:heartbeat:$deploy_provider_id" 2>/dev/null | tr -d '\r')"
  if [[ "$ttl" =~ ^[0-9]+$ ]] && (( ttl > 0 )); then
    heartbeat_ready=1
    break
  fi
  sleep 1
done
[[ -n "$heartbeat_ready" ]]

cd "$repo_root"
submit_output="$(OPENINFRA_API_KEY="$deploy_api_key" "$workloadctl_bin" submit "$deploy_image_ref" 0.1 64 0 300)"
deploy_workload_id="$(sed -n 's/^workload_id: //p' <<<"$submit_output")"
[[ "$deploy_workload_id" =~ ^[0-9a-f-]{36}$ ]]
grep -q "state: WORKLOAD_STATE_REQUESTED" <<<"$submit_output"

# The full REQUESTED -> SCHEDULING -> LEASE_PENDING -> LEASED -> DEPLOYING
# -> RUNNING pipeline crosses two on-chain finality waits (lease creation,
# then the Agent's own Deploy round-trip); 90 x 3s gives it generous room
# without hanging forever on a genuine regression.
deploy_state=""
get_output=""
for _ in $(seq 1 90); do
  get_output="$(OPENINFRA_API_KEY="$deploy_api_key" "$workloadctl_bin" get "$deploy_workload_id")"
  deploy_state="$(sed -n 's/^state: //p' <<<"$get_output")"
  [[ "$deploy_state" == "WORKLOAD_STATE_RUNNING" || "$deploy_state" == "WORKLOAD_STATE_FAILED" ]] && break
  sleep 3
done
if [[ "$deploy_state" != "WORKLOAD_STATE_RUNNING" ]]; then
  echo "workload $deploy_workload_id never reached RUNNING (last state: $deploy_state)" >&2
  echo "$get_output" >&2
  exit 1
fi
deploy_container_id="$(sed -n 's/^container_id: //p' <<<"$get_output")"
[[ -n "$deploy_container_id" ]]

# Verify the container is real on the provider (Docker) side, not just a
# state string in Postgres.
[[ "$(docker inspect --format='{{.State.Running}}' "$deploy_container_id")" == "true" ]]

echo "E2E SubmitWorkload -> Deploy -> RUNNING passed for workload $deploy_workload_id (container $deploy_container_id on provider $deploy_provider_id)"
