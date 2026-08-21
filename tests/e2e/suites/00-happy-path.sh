#!/usr/bin/env bash
# Suite 00: the full target lifecycle against the real Compose stack --
# Join -> ACTIVE -> offer -> lease -> deploy -> observe -> stop -> reward.
# Single provider, single tenant, no injected failures: this is the
# baseline every other suite in tests/e2e/ builds on top of. Historically
# this suite's content was the entirety of tests/e2e/run.sh (issue #117);
# it now lives here as one suite among several, run.sh dispatches it.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export E2E_REPO_ROOT="$repo_root"
# shellcheck source=tests/e2e/lib/common.sh
. "$repo_root/tests/e2e/lib/common.sh"

require_stack_up postgres redis blockchain-node control-plane docker-socket-proxy provider-agent

test_dir="$(mktemp -d)"
register_cleanup "rm -rf \"$test_dir\""

# --- Join + heartbeat (issue #16) ---------------------------------------
provider_id=""
(
  cd "$test_dir"
  "$E2E_BIN_DIR/agent-cli" init >/dev/null
)
eval "$(agent_client_tls_env)"

join_output="$(agent_join_with_retry "$test_dir")" || fail "join did not succeed after 5 attempts"
provider_id="$(sed -n 's/^Provider ACTIVE: //p' <<<"$join_output")"
[[ "$provider_id" =~ ^[0-9a-f]{64}$ ]] || fail "join did not report a valid provider_id"
register_cleanup "redis_exec DEL \"openinfra:heartbeat:$provider_id\" >/dev/null 2>&1 || true"
register_cleanup "psql_exec \"DELETE FROM provider_chain_registrations WHERE provider_id='$provider_id'; DELETE FROM provider_join_completions WHERE provider_id='$provider_id'; DELETE FROM provider_join_challenges WHERE provider_id='$provider_id'; DELETE FROM providers WHERE provider_id='$provider_id';\" >/dev/null 2>&1 || true"

heartbeat_output="$(cd "$test_dir" && timeout 20s "$E2E_BIN_DIR/agent-cli" heartbeat)"
grep -q "Provider ACTIVE: $provider_id (heartbeat 1)" <<<"$heartbeat_output" || fail "heartbeat did not report ACTIVE"
[[ "$(redis_exec HGET "openinfra:heartbeat:$provider_id" sequence | tr -d '\r')" == "1" ]] || fail "heartbeat sequence not cached in Redis"
heartbeat_ttl_positive "$provider_id" || fail "heartbeat TTL not positive after heartbeat"

log "Join + Heartbeat passed for $provider_id"

# --- offer (ADR: resource-market reconciler mirrors capacity on-chain) --
# Checked against *some* schedulable provider in the stack (not
# necessarily $provider_id above): resourcemarket.Reconciler only
# publishes an offer once every 30s (DefaultReconcilerConfig) and that
# publish is itself an on-chain extrinsic with its own finality wait, so
# a provider whose one-shot join+heartbeat TTL expires in under a minute
# is a genuinely flaky thing to assert an offer appeared *for it*
# specifically. The always-on Compose provider-agent (a real, continuously
# heartbeating provider, not this suite's disposable one) is what actually
# proves the offer pipeline works end to end here.
overview_url="${E2E_DASHBOARD_URL:-http://127.0.0.1:8080}/api/v1/overview"
wait_until 90 3 "at least one provider has a found on-chain offer on /api/v1/overview" \
  bash -c "curl -fsS '$overview_url' | grep -q '\"offer\":{\"found\":true'" \
  || fail "no provider in the stack has a found on-chain offer (offer reconciliation)"
log "Offer observed via $overview_url"

# --- dashboard RBAC + tenant isolation (issue #76) ----------------------
cd "$repo_root/control-plane"
E2E_DASHBOARD_URL="${E2E_DASHBOARD_URL:-http://127.0.0.1:8080}" \
E2E_GRPC_ADDR="${CONTROL_PLANE_GRPC_ADDR:-127.0.0.1:50051}" \
E2E_COMPOSE="${compose[*]}" \
  go test -tags e2e -count=1 -timeout 10m -run 'TestE2E' ./internal/dashboard/
log "Dashboard RBAC + tenant isolation passed"

# --- SubmitWorkload -> lease -> deploy -> RUNNING (issue #117) ----------
# Deployed onto a second, disposable provider this suite joins itself
# (start_provider_agent), not the always-on Compose provider-agent --
# even though that agent is already ACTIVE and would save a join. This is
# how the original pre-restructure tests/e2e/run.sh's "second provider"
# already worked, and is kept for the same reason: it gives the suite a
# provider it fully owns and controls (registered fresh, cleaned up
# unconditionally), independent of whatever else is scheduled onto the
# shared Compose agent by other suites or tests running in the same
# session (notably control-plane/internal/dashboard's own e2e_rbac_test.go,
# exercised a few lines above this). While developing this suite matrix
# this same independence also incidentally routed around two real
# Provider Agent bugs this session found and fixed directly
# (BollardEngine::connect() not honoring a tcp:// DOCKER_HOST, and
# get_status() hard-erroring instead of reporting a clean status for a
# container-less/just-removed workload -- see provider-agent/crates/
# agent-executor/src/lib.rs and the follow-up issue filed alongside this
# suite matrix for what's still open) -- the Compose agent path is
# confirmed working now too (both are exercised across this suite
# matrix), but there is no reason to give this suite two live providers
# to reason about when one, fully owned, is simpler and already proves
# the same lease->deploy->RUNNING pipeline.
deploy_agent_dir="$(mktemp -d)"
deploy_provider_id="$(start_provider_agent "$deploy_agent_dir" 50098)" \
  || fail "deploy agent failed to join/start"

create_user_output="$("$E2E_BIN_DIR/controlplane-admin" create-user "e2e-happy-path")"
deploy_user_id="$(sed -n 's/^user_id: //p' <<<"$create_user_output")"
deploy_api_key="$(sed -n 's/^api_key: //p' <<<"$create_user_output" | awk '{print $1}')"
[[ "$deploy_user_id" =~ ^[0-9a-f-]{36}$ ]] || fail "create-user did not return a user_id"
[[ "$deploy_api_key" =~ ^oiu_[0-9a-f]{64}$ ]] || fail "create-user did not return an api_key"
register_cleanup "psql_exec \"DELETE FROM api_keys WHERE user_id='$deploy_user_id'; DELETE FROM users WHERE user_id='$deploy_user_id';\" >/dev/null 2>&1 || true"

# A small, well-known image pinned by digest (validateSubmission requires
# it). registry.k8s.io/pause, not alpine/nginx: the Agent's executor runs
# every container with cap_drop=ALL + no-new-privileges, and pause's whole
# job is to sit idle forever with zero privileges.
deploy_image="registry.k8s.io/pause:3.9"
docker pull -q "$deploy_image" >/dev/null
deploy_image_ref="$(docker inspect --format='{{index .RepoDigests 0}}' "$deploy_image")"

cd "$repo_root"
submit_output="$(OPENINFRA_API_KEY="$deploy_api_key" "$E2E_BIN_DIR/workloadctl" submit "$deploy_image_ref" 0.1 64 0 300)"
deploy_workload_id="$(sed -n 's/^workload_id: //p' <<<"$submit_output")"
[[ "$deploy_workload_id" =~ ^[0-9a-f-]{36}$ ]] || fail "submit did not return a workload_id"
grep -q "state: WORKLOAD_STATE_REQUESTED" <<<"$submit_output" || fail "submit did not report REQUESTED"
register_cleanup "psql_exec \"DELETE FROM workloads WHERE workload_id='$deploy_workload_id';\" >/dev/null 2>&1 || true"

# The full REQUESTED -> SCHEDULING -> LEASE_PENDING -> LEASED -> DEPLOYING
# -> RUNNING pipeline crosses two on-chain finality waits; 90 x 3s gives it
# generous room without hanging forever on a genuine regression.
deploy_state="" get_output="" deploy_container_id="" deploy_provider_id=""
for _ in $(seq 1 90); do
  get_output="$(OPENINFRA_API_KEY="$deploy_api_key" "$E2E_BIN_DIR/workloadctl" get "$deploy_workload_id")"
  deploy_state="$(sed -n 's/^state: //p' <<<"$get_output")"
  deploy_container_id="$(sed -n 's/^container_id: //p' <<<"$get_output")"
  deploy_provider_id="$(sed -n 's/^provider_id: //p' <<<"$get_output")"
  [[ "$deploy_state" == "WORKLOAD_STATE_RUNNING" || "$deploy_state" == "WORKLOAD_STATE_FAILED" ]] && break
  sleep 3
done
if [[ -n "$deploy_container_id" ]]; then
  # BollardEngine's containers are independent dockerd-managed processes,
  # so this is registered as soon as we ever observe one -- if the loop
  # below fails after this point, cleanup still removes the real container.
  register_cleanup "docker rm -f \"$deploy_container_id\" >/dev/null 2>&1 || true"
fi
[[ "$deploy_state" == "WORKLOAD_STATE_RUNNING" ]] || fail "workload $deploy_workload_id never reached RUNNING (last state: $deploy_state; $get_output)"
[[ -n "$deploy_container_id" ]] || fail "RUNNING workload has no container_id"
[[ -n "$deploy_provider_id" ]] || fail "RUNNING workload has no provider_id"
[[ "$(docker inspect --format='{{.State.Running}}' "$deploy_container_id")" == "true" ]] || fail "reported container is not actually running"

log "Lease + Deploy -> RUNNING passed for workload $deploy_workload_id (container $deploy_container_id on provider $deploy_provider_id)"

# --- observe: reward points readable on-chain (pallet-rewards) ---------
onchain_url="${E2E_DASHBOARD_URL:-http://127.0.0.1:8080}/api/v1/provider/$deploy_provider_id/onchain"
onchain_output="$(curl -fsS "$onchain_url")" || fail "provider onchain endpoint unreachable"
grep -q '"available":true' <<<"$onchain_output" || fail "provider onchain earnings read unavailable: $onchain_output"
# A short-lived local devnet reward-accrual cadence is validator-round
# based (ADR-013): this only asserts the read path works end to end, not
# that RewardPoints > 0 -- see tests/e2e/AGENTS.md for why balance-growth
# is out of scope for this suite's timebox.
grep -q '"reward_points"' <<<"$onchain_output" || fail "provider onchain response missing reward_points"
log "Reward Points observable via $onchain_url: $onchain_output"

# --- stop: explicit StopWorkload -> STOPPED, not just cleanup ----------
OPENINFRA_API_KEY="$deploy_api_key" "$E2E_BIN_DIR/workloadctl" stop "$deploy_workload_id" >/dev/null
stop_state=""
for _ in $(seq 1 20); do
  stop_state="$(OPENINFRA_API_KEY="$deploy_api_key" "$E2E_BIN_DIR/workloadctl" get "$deploy_workload_id" 2>/dev/null | sed -n 's/^state: //p')" || true
  [[ "$stop_state" == "WORKLOAD_STATE_STOPPED" || "$stop_state" == "WORKLOAD_STATE_FAILED" ]] && break
  sleep 3
done
[[ "$stop_state" == "WORKLOAD_STATE_STOPPED" ]] || fail "workload $deploy_workload_id never reached STOPPED (last state: $stop_state)"
# 90s: registry.k8s.io/pause has no SIGTERM handler (its entire job is to
# sit idle), so bollard's stop_container grace period (agent-executor's
# StopContainerOptions{t: 10}) routinely runs its full 10s before Docker
# SIGKILLs it, on top of remove_container and the gRPC round trip --
# confirmed live, twice, on a busy stack: 20s and then 40s each flaked
# here even though the container was, in fact, removed correctly a few
# seconds later both times. Generous on purpose rather than chasing the
# exact number further -- this check's job is to catch a genuine leak,
# not to pin down this host's exact Docker stop latency.
wait_until 90 1 "container $deploy_container_id removed after stop" \
  bash -c "! docker inspect \"$deploy_container_id\" >/dev/null 2>&1" \
  || fail "container $deploy_container_id still present after StopWorkload reported STOPPED"

log "Stop passed: workload $deploy_workload_id STOPPED and container $deploy_container_id removed"

# --- idempotence: re-driving Stop on an already-stopped workload -------
restop_output="$(OPENINFRA_API_KEY="$deploy_api_key" "$E2E_BIN_DIR/workloadctl" stop "$deploy_workload_id" 2>&1)" || true
restop_state="$(OPENINFRA_API_KEY="$deploy_api_key" "$E2E_BIN_DIR/workloadctl" get "$deploy_workload_id" | sed -n 's/^state: //p')"
[[ "$restop_state" == "WORKLOAD_STATE_STOPPED" ]] || fail "re-driving stop mutated a STOPPED workload's state (got $restop_state): $restop_output"
container_count="$(psql_exec "SELECT count(*) FROM workloads WHERE workload_id='$deploy_workload_id';" | tr -d '[:space:]')"
[[ "$container_count" == "1" ]] || fail "re-driving stop duplicated the workload row (count=$container_count)"

log "Idempotence passed: re-driving Stop on workload $deploy_workload_id caused no duplicate row/state change"

echo "E2E happy-path suite PASSED"
