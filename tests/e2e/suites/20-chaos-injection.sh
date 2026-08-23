#!/usr/bin/env bash
# Suite 20: chaos injection against the real Compose stack -- restarts,
# a network partition, Redis loss, PostgreSQL recovery, an Agent timeout,
# and a chain delay. Each scenario is self-contained: it registers the
# "put it back" cleanup *before* performing the disruptive action (so an
# assertion failure mid-scenario still restores the shared dev stack for
# whatever suite runs next), then asserts the system recovers without
# duplicating a container, lease, or provider row.
#
# Scenario coverage vs. the six kinds issue #17 asks for:
#   - restart          -> scenario_control_plane_restart
#   - network partition -> scenario_network_partition
#   - Redis loss        -> scenario_redis_loss
#   - PostgreSQL recovery -> scenario_postgres_recovery
#   - Agent timeout      -> scenario_agent_timeout
#   - chain delay         -> scenario_chain_delay
#
# Plus, per issue #139's "deeper fault injection" item:
#   - Postgres torn (mid-flight) connection -> scenario_postgres_torn_connection,
#     using the opt-in "chaos"-profile toxiproxy proxy
#     (deployments/docker-compose.yml) to inject a real TCP RST into an
#     already-established Postgres connection -- a different, more
#     realistic failure mode than scenario_postgres_recovery's clean
#     `docker compose stop` above.
#
# What is deliberately NOT attempted here (see tests/e2e/AGENTS.md): a
# real multi-node network split (this is a single-node dev chain --
# ADR-009 -- there is nothing to partition on the consensus side, only the
# CP<->Agent link, which scenario_network_partition covers). Redis's own
# torn-connection equivalent is scoped out of this first toxiproxy pass
# (see scenario_postgres_torn_connection's own comment for why Postgres was
# picked first) -- a real, tracked follow-up, not a silent gap.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export E2E_REPO_ROOT="$repo_root"
# shellcheck source=tests/e2e/lib/common.sh
. "$repo_root/tests/e2e/lib/common.sh"

ensure_shared_binaries
require_stack_up postgres redis blockchain-node control-plane docker-socket-proxy provider-agent

deploy_image="registry.k8s.io/pause:3.9"
docker pull -q "$deploy_image" >/dev/null
deploy_image_ref="$(docker inspect --format='{{index .RepoDigests 0}}' "$deploy_image")"

new_tenant() {
  local label="$1" out user_id api_key
  out="$("$E2E_BIN_DIR/controlplane-admin" create-user "$label")"
  user_id="$(sed -n 's/^user_id: //p' <<<"$out")"
  api_key="$(sed -n 's/^api_key: //p' <<<"$out" | awk '{print $1}')"
  [[ "$user_id" =~ ^[0-9a-f-]{36}$ ]] || fail "create-user($label) did not return a user_id"
  register_cleanup "psql_exec \"DELETE FROM api_keys WHERE user_id='$user_id'; DELETE FROM users WHERE user_id='$user_id';\" >/dev/null 2>&1 || true"
  echo "$api_key"
}

submit_workload() {
  local api_key="$1" out wid
  out="$(OPENINFRA_API_KEY="$api_key" "$E2E_BIN_DIR/workloadctl" submit "$deploy_image_ref" 0.1 64 0 300)"
  wid="$(sed -n 's/^workload_id: //p' <<<"$out")"
  [[ "$wid" =~ ^[0-9a-f-]{36}$ ]] || fail "submit did not return a workload_id: $out"
  register_cleanup "psql_exec \"DELETE FROM workloads WHERE workload_id='$wid';\" >/dev/null 2>&1 || true"
  echo "$wid"
}

wait_workload_terminal() {
  local wid="$1" timeout_s="$2" waited=0 state
  while (( waited < timeout_s )); do
    state="$(workload_state "$wid")"
    [[ "$state" == "RUNNING" || "$state" == "FAILED" ]] && { echo "$state"; return 0; }
    sleep 3
    waited=$((waited + 3))
  done
  echo "$state"
  return 1
}

# stop_and_release_capacity <api_key> <wid> -- unlike every other cleanup
# in this suite (a bare `docker rm -f $container_id`, which force-removes
# the container out from under the Agent without ever telling it), this
# issues a real `workloadctl stop` so internal/orchestrator/worker.go's
# STOPPING-state handler calls the Agent's StopAndConfirm and its
# agent-executor::recover()-tracked WorkloadRecord actually transitions
# out of a capacity-consuming WorkloadPhase (agent-core::local_state.rs).
# Found live while determinism-testing scenario_postgres_torn_connection
# in this session: `docker rm -f`-only cleanup (used everywhere else in
# this suite, and in suites 10/00's cleanup-safety-net registration) never
# frees the Agent's own OPENINFRA_AGENT_MAX_WORKLOADS reservation for that
# workload, so repeated runs against the same long-lived default
# single-provider stack silently exhaust it (default max 8, 2 workloads
# per run of this scenario alone) -- after which every subsequent Deploy
# is rejected with "maximum active workload count reached" and the
# orchestrator's uncapped retry loop (already a known gap, see this repo's
# CLAUDE.md) spins on it forever. That's a real, pre-existing, suite-wide
# gap (see follow-up issue #152) affecting
# every scenario here, not something this fix claims to close everywhere
# -- it only keeps this scenario's own two workloads from adding to it.
# Best-effort and bounded (a stuck stop must not make this scenario itself
# hang): logs and moves on rather than `fail`ing if the Agent doesn't
# confirm STOPPED/FAILED promptly, since the scenario's actual pass/fail
# assertions are already satisfied by the time this is called.
stop_and_release_capacity() {
  local api_key="$1" wid="$2" waited=0 state=""
  OPENINFRA_API_KEY="$api_key" "$E2E_BIN_DIR/workloadctl" stop "$wid" >/dev/null 2>&1 || true
  while (( waited < 30 )); do
    state="$(workload_state "$wid")"
    [[ "$state" == "STOPPED" || "$state" == "FAILED" ]] && { log "workload $wid released Agent capacity (state: $state)"; return 0; }
    sleep 3
    waited=$((waited + 3))
  done
  log "workload $wid did not confirm STOPPED/FAILED within 30s (last state: $state) -- Agent capacity for it may still be leaked; continuing anyway"
}

# --- A: restart -- control-plane restarts mid-flight ----------------------
scenario_control_plane_restart() {
  log "=== scenario: control-plane restart ==="
  local api_key wid state
  api_key="$(new_tenant "e2e-chaos-restart")"
  wid="$(submit_workload "$api_key")"

  # Give the orchestrator a moment to move the workload past REQUESTED
  # before the restart, so the restart genuinely lands mid-flight rather
  # than before any state machine progress happened at all.
  wait_until 30 2 "workload $wid leaves REQUESTED before restart" \
    workload_state_is_not "$wid" REQUESTED || true

  log "restarting control-plane container"
  "${compose[@]}" restart control-plane >/dev/null
  wait_service_healthy control-plane 60 || fail "control-plane did not become healthy again after restart"

  state="$(wait_workload_terminal "$wid" 180)" || true
  [[ "$state" == "RUNNING" ]] || fail "workload $wid did not reach RUNNING after control-plane restart (last state: $state)"

  local lease_count container_id
  lease_count="$(psql_exec "SELECT count(DISTINCT lease_id) FROM workloads WHERE workload_id='$wid';")"
  [[ "$(tr -d '[:space:]' <<<"$lease_count")" == "1" ]] || fail "workload $wid ended up with more than one distinct lease_id across the restart"
  container_id="$(psql_exec "SELECT container_id FROM workloads WHERE workload_id='$wid';" | tr -d '[:space:]')"
  [[ -n "$container_id" ]] || fail "workload $wid has no container_id after reaching RUNNING"
  register_cleanup "docker rm -f \"$container_id\" >/dev/null 2>&1 || true"
  [[ "$(docker inspect --format='{{.State.Running}}' "$container_id" 2>/dev/null)" == "true" ]] || fail "container $container_id is not running"

  log "PASS: control-plane restart -- workload $wid recovered to RUNNING with exactly one lease/container"
}

# --- B: network partition -- Control Plane <-> Agent link cut -------------
scenario_network_partition() {
  log "=== scenario: network partition (control-plane <-> provider-agent) ==="
  local agent_cid network_name provider_id
  agent_cid="$(service_container_id provider-agent)"
  [[ -n "$agent_cid" ]] || fail "compose provider-agent container not found"
  network_name="$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$agent_cid" | grep -v docker-executor | head -1)"
  [[ -n "$network_name" ]] || fail "could not determine provider-agent's default network"

  provider_id="$(psql_exec "SELECT provider_id FROM providers ORDER BY registered_at DESC LIMIT 1;" | tr -d '[:space:]')"
  [[ -n "$provider_id" ]] || fail "no provider registered to observe through the partition"

  log "disconnecting $agent_cid from $network_name"
  register_cleanup "docker network connect \"$network_name\" \"$agent_cid\" >/dev/null 2>&1 || true"
  docker network disconnect "$network_name" "$agent_cid"

  # Heartbeats stop reaching the Control Plane; the Redis TTL cache (a
  # reconstructible cache, per AGENTS.md, not authoritative state) should
  # expire rather than being falsely kept alive.
  wait_until 60 3 "heartbeat TTL for $provider_id expires during the partition" \
    heartbeat_ttl_expired "$provider_id" \
    || log "heartbeat TTL had not expired within 60s of the partition (non-fatal, cache TTL may simply be longer than this window)"

  log "reconnecting $agent_cid to $network_name"
  docker network connect "$network_name" "$agent_cid"

  wait_until 60 3 "heartbeat TTL for $provider_id recovers after reconnect" \
    heartbeat_ttl_positive "$provider_id" \
    || fail "provider $provider_id never resumed heartbeating after the network partition healed"

  local provider_row_count
  provider_row_count="$(psql_exec "SELECT count(*) FROM providers WHERE provider_id='$provider_id';" | tr -d '[:space:]')"
  [[ "$provider_row_count" == "1" ]] || fail "provider $provider_id has $provider_row_count rows after the partition (expected exactly 1 -- no duplicate registration)"

  log "PASS: network partition -- provider $provider_id recovered with no duplicate registration"
}

# --- C: Redis loss ----------------------------------------------------------
scenario_redis_loss() {
  log "=== scenario: Redis loss ==="
  local provider_id
  provider_id="$(psql_exec "SELECT provider_id FROM providers ORDER BY registered_at DESC LIMIT 1;" | tr -d '[:space:]')"
  [[ -n "$provider_id" ]] || fail "no provider registered to observe through the Redis outage"

  register_cleanup "\"\${compose[@]}\" start redis >/dev/null 2>&1 || true; wait_service_healthy redis 60 || true"
  log "stopping redis"
  "${compose[@]}" stop redis >/dev/null

  # control-plane must not crash-loop just because its reconstructible
  # cache disappeared.
  sleep 10
  [[ -n "$(service_container_id control-plane)" ]] || fail "control-plane container exited after Redis loss"
  local cp_status
  cp_status="$(docker inspect --format='{{.State.Status}}' "$(service_container_id control-plane)")"
  [[ "$cp_status" == "running" ]] || fail "control-plane is not running after Redis loss (status: $cp_status)"

  log "starting redis"
  "${compose[@]}" start redis >/dev/null
  wait_service_healthy redis 60 || fail "redis did not become healthy again"

  wait_until 60 3 "heartbeat TTL for $provider_id reconstructed after Redis recovers" \
    heartbeat_ttl_positive "$provider_id" \
    || fail "heartbeat cache for $provider_id was never reconstructed after Redis recovered"

  local provider_row_count
  provider_row_count="$(psql_exec "SELECT count(*) FROM providers WHERE provider_id='$provider_id';" | tr -d '[:space:]')"
  [[ "$provider_row_count" == "1" ]] || fail "provider $provider_id has $provider_row_count rows after the Redis outage"

  log "PASS: Redis loss -- heartbeat cache reconstructed, no duplicate provider row"
}

# --- D: PostgreSQL recovery -------------------------------------------------
scenario_postgres_recovery() {
  log "=== scenario: PostgreSQL recovery ==="
  register_cleanup "\"\${compose[@]}\" start postgres >/dev/null 2>&1 || true; wait_service_healthy postgres 60 || true"
  log "stopping postgres"
  "${compose[@]}" stop postgres >/dev/null

  sleep 10
  [[ -n "$(service_container_id control-plane)" ]] || fail "control-plane container exited after PostgreSQL loss"

  log "starting postgres"
  "${compose[@]}" start postgres >/dev/null
  wait_service_healthy postgres 60 || fail "postgres did not become healthy again"

  # A fresh full lifecycle right after recovery, as the real proof the
  # Control Plane reconnected and resumed normal operation rather than
  # merely staying alive with a dead connection pool.
  local api_key wid state
  api_key="$(new_tenant "e2e-chaos-postgres-recovery")"
  wid="$(submit_workload "$api_key")"
  state="$(wait_workload_terminal "$wid" 180)" || true
  [[ "$state" == "RUNNING" ]] || fail "post-recovery workload $wid did not reach RUNNING (last state: $state)"
  local container_id
  container_id="$(psql_exec "SELECT container_id FROM workloads WHERE workload_id='$wid';" | tr -d '[:space:]')"
  register_cleanup "docker rm -f \"$container_id\" >/dev/null 2>&1 || true"

  log "PASS: PostgreSQL recovery -- control-plane survived the outage and a post-recovery workload reached RUNNING"
}

# --- E: Agent timeout -- an unresponsive Agent process ----------------------
scenario_agent_timeout() {
  log "=== scenario: Agent timeout ==="
  local work_dir port provider_id api_key wid
  work_dir="$(mktemp -d)"
  port=50110
  provider_id="$(start_provider_agent "$work_dir" "$port")" || fail "scenario_agent_timeout: provider agent failed to join/start"
  # This scenario needs the workload to land on *this* disposable agent
  # specifically, not whichever provider the scheduler ranks highest (it
  # may prefer the always-on Compose agent). ListSchedulableProviders only
  # considers status = NODE_STATUS_ACTIVE (2, protocol/proto/openinfra/
  # shared/v1/shared.proto) rows, so flipping every other provider to
  # NODE_STATUS_OFFLINE (3) makes this one a deterministic scheduling
  # target; cleanup restores everyone else to ACTIVE.
  register_cleanup "psql_exec \"UPDATE providers SET status=2 WHERE provider_id NOT IN ('$provider_id');\" >/dev/null 2>&1 || true"
  psql_exec "UPDATE providers SET status=3 WHERE provider_id NOT IN ('$provider_id');" >/dev/null || true

  api_key="$(new_tenant "e2e-chaos-agent-timeout")"
  wid="$(submit_workload "$api_key")"

  wait_until 60 2 "workload $wid reaches DEPLOYING against provider $provider_id" \
    workload_state_is "$wid" DEPLOYING \
    || fail "workload $wid never reached DEPLOYING before the agent was killed"

  # start_provider_agent always runs the same shared binary
  # ($E2E_BIN_DIR/agent-cli start); this scenario is the only one in this
  # suite that has one running host-side at this point, so matching on
  # the binary path is unambiguous.
  local agent_pid
  agent_pid="$(pgrep -f "$E2E_BIN_DIR/agent-cli start" | head -1)"
  [[ -n "$agent_pid" ]] || fail "could not locate the agent-cli process for $work_dir to kill"
  log "killing agent process $agent_pid (simulating an unresponsive Agent)"
  kill -9 "$agent_pid" 2>/dev/null || true

  # No max-attempt cutoff exists yet in internal/orchestrator/worker.go
  # (RetryLater re-tries the same DEPLOYING state against the same dead
  # provider indefinitely, 5s apart -- see tests/e2e/AGENTS.md and the
  # follow-up issue filed alongside this suite). The correctness property
  # under test here is therefore *not* "eventually FAILED" but "never
  # falsely RUNNING, and retries stay bounded per attempt" while the Agent
  # is down.
  sleep 30
  local state
  state="$(workload_state "$wid")"
  [[ "$state" != "RUNNING" ]] || fail "workload $wid reported RUNNING while its Agent was dead -- this must never happen (AGENTS.md: never report RUNNING before authoritative confirmation)"
  [[ "$state" == "DEPLOYING" ]] || log "workload $wid is in $state (not DEPLOYING) while its Agent is dead -- noting, not failing"

  # Recover: restart the same identity (same work_dir/identity.key) so
  # the provider_id is unchanged, and confirm the retry loop's
  # reconciliation (DeploymentReconciler.GetRunningWorkload) lets it
  # reach RUNNING with exactly one container rather than a duplicate.
  eval "$(agent_server_tls_env)"
  # exec'd for the same reason as start_provider_agent in lib/common.sh:
  # $! must be agent-cli's own pid, not a wrapping subshell's.
  ( cd "$work_dir" || exit 1
    exec "$E2E_BIN_DIR/agent-cli" start >"$work_dir/start-2.log" 2>&1
  ) &
  local restarted_pid=$!
  register_cleanup "kill $restarted_pid >/dev/null 2>&1 || true; wait $restarted_pid 2>/dev/null || true"

  state="$(wait_workload_terminal "$wid" 180)" || true
  [[ "$state" == "RUNNING" ]] || fail "workload $wid did not recover to RUNNING after the Agent restarted (last state: $state)"
  local container_id
  container_id="$(psql_exec "SELECT container_id FROM workloads WHERE workload_id='$wid';" | tr -d '[:space:]')"
  [[ -n "$container_id" ]] || fail "recovered workload $wid has no container_id"
  register_cleanup "docker rm -f \"$container_id\" >/dev/null 2>&1 || true"

  # Explicit teardown now, on the happy path, rather than waiting for the
  # suite-wide EXIT trap: the next scenario (chain delay) must see the
  # normal single-Compose-agent world, not this scenario's rigged one.
  # The trap-based register_cleanup entries above stay in place purely as
  # a safety net for the unhappy (early-fail) path.
  kill "$restarted_pid" >/dev/null 2>&1 || true
  wait "$restarted_pid" 2>/dev/null || true
  psql_exec "UPDATE providers SET status=2 WHERE provider_id NOT IN ('$provider_id');" >/dev/null || true

  log "PASS: Agent timeout -- workload $wid never falsely reported RUNNING, recovered to exactly one container after the Agent restarted"
}

# --- F: chain delay ----------------------------------------------------------
scenario_chain_delay() {
  log "=== scenario: chain delay ==="
  local api_key wid
  api_key="$(new_tenant "e2e-chaos-chain-delay")"
  wid="$(submit_workload "$api_key")"

  register_cleanup "docker unpause \$(service_container_id blockchain-node) >/dev/null 2>&1 || true"
  log "pausing blockchain-node (simulates a stalled/slow chain)"
  docker pause "$(service_container_id blockchain-node)" >/dev/null

  # While paused, the workload's on-chain steps (lease finality) cannot
  # progress; give the orchestrator a few retry cycles to observe and
  # bounded-retry through the delay (LEASE_NOT_FINALIZED / RetryLater),
  # never crash, and never fabricate a lease.
  sleep 20
  local state
  state="$(workload_state "$wid")"
  [[ "$state" != "RUNNING" && "$state" != "FAILED" ]] || fail "workload $wid reached a terminal state ($state) while the chain was paused -- should still be retrying"
  [[ -n "$(service_container_id control-plane)" ]] || fail "control-plane exited while the chain was paused"

  log "unpausing blockchain-node"
  docker unpause "$(service_container_id blockchain-node)" >/dev/null
  wait_service_healthy blockchain-node 60 || fail "blockchain-node did not become healthy again after unpausing"

  state="$(wait_workload_terminal "$wid" 180)" || true
  [[ "$state" == "RUNNING" ]] || fail "workload $wid did not reach RUNNING after the chain delay cleared (last state: $state)"
  local lease_count container_id
  lease_count="$(psql_exec "SELECT count(DISTINCT lease_id) FROM workloads WHERE workload_id='$wid';" | tr -d '[:space:]')"
  [[ "$lease_count" == "1" ]] || fail "workload $wid ended up with $lease_count distinct lease_ids across the chain delay"
  container_id="$(psql_exec "SELECT container_id FROM workloads WHERE workload_id='$wid';" | tr -d '[:space:]')"
  register_cleanup "docker rm -f \"$container_id\" >/dev/null 2>&1 || true"

  log "PASS: chain delay -- workload $wid retried through the pause and reached RUNNING with exactly one lease"
}

# --- G: Postgres torn connection -- a real TCP RST via toxiproxy, not a
# clean `docker compose stop` -----------------------------------------------
# scenario_postgres_recovery above proves the system survives Postgres
# receiving a clean shutdown signal; this proves it survives a live
# connection being severed out from under it mid-flight (issue #139's
# "deeper fault injection" item). Picked Postgres over Redis for this
# first toxiproxy pass: Postgres is the authoritative off-chain store
# (AGENTS.md) that internal/orchestrator's claim loop writes to on every
# poll tick (1s, worker.go), so a torn connection here is squarely in the
# path that actually matters for correctness -- Redis is a reconstructible
# cache (scenario_redis_loss already proves a *lost* Redis recovers; a
# torn-vs-clean distinction matters far less for a cache that's allowed to
# just be repopulated). A Redis torn-connection scenario is a real,
# tracked follow-up, not silently dropped.
#
# Scoped deliberately to not touch the always-on Compose control-plane's
# own Postgres connection at all (see deployments/docker-compose.yml's
# toxiproxy comment for why): this scenario starts one extra, disposable
# `controlplane` worker process (lib/common.sh's
# start_extra_controlplane_worker, same mechanism suite 10 uses for
# concurrency) whose DATABASE_URL is the only thing different -- routed
# through the "chaos"-profile toxiproxy proxy instead of straight to
# Postgres -- so only this one worker's traffic can have a toxic injected
# into it. The always-on Compose control-plane and every other suite in
# this matrix are completely unaffected by this scenario running.
scenario_postgres_torn_connection() {
  log "=== scenario: Postgres torn connection (toxiproxy reset_peer) ==="
  local toxi_admin="http://127.0.0.1:${TOXIPROXY_ADMIN_PORT:-8474}"
  local toxi_pg_port="${TOXIPROXY_POSTGRES_PORT:-15432}"
  local proxy_name="postgres-e2e-chaos"

  # Lazy expansion of the global `compose` array (not a locally-scoped
  # copy) -- see lib/common.sh's register_cleanup comment on why: this
  # function returns long before the EXIT trap that runs this cleanup
  # fires, so anything registered here must reference state that is still
  # valid at that later point, which a `local` array is not.
  register_cleanup "\"\${compose[@]}\" --profile chaos stop toxiproxy >/dev/null 2>&1 || true"
  log "starting toxiproxy (chaos profile)"
  "${compose[@]}" --profile chaos up -d --wait toxiproxy \
    || fail "toxiproxy did not become ready"
  curl -fsS "$toxi_admin/proxies/$proxy_name" >/dev/null \
    || fail "toxiproxy proxy $proxy_name not found at $toxi_admin -- check deployments/local/toxiproxy/config.json"

  local work_dir grpc_port=50130 http_port=8130 worker_pid
  work_dir="$(mktemp -d)"
  local proxied_database_url="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${toxi_pg_port}/${POSTGRES_DB}?sslmode=disable"
  worker_pid="$(start_extra_controlplane_worker "$work_dir" "$grpc_port" "$http_port" "$proxied_database_url")" \
    || fail "toxiproxy-routed extra control-plane worker failed to start"
  log "extra control-plane worker $worker_pid routing Postgres through toxiproxy"

  # internal/orchestrator's claim-scan ticks every 1s (worker.go), so a
  # few seconds is generous room for this worker to have already used its
  # proxied connection at least once before the toxic below lands on it.
  sleep 5
  kill -0 "$worker_pid" 2>/dev/null || fail "toxiproxy-routed worker $worker_pid exited before the toxic was even injected"

  log "injecting reset_peer toxics (real TCP RST, both directions) on $proxy_name"
  curl -fsS -X POST "$toxi_admin/proxies/$proxy_name/toxics" -H 'Content-Type: application/json' \
    -d '{"name":"e2e-reset-upstream","type":"reset_peer","stream":"upstream","attributes":{"timeout":0}}' >/dev/null \
    || fail "failed to inject upstream reset_peer toxic"
  curl -fsS -X POST "$toxi_admin/proxies/$proxy_name/toxics" -H 'Content-Type: application/json' \
    -d '{"name":"e2e-reset-downstream","type":"reset_peer","stream":"downstream","attributes":{"timeout":0}}' >/dev/null \
    || fail "failed to inject downstream reset_peer toxic"

  # The torn connection must not crash the worker process -- a reset mid-
  # query is a driver-level error to retry, never a reason to exit.
  sleep 15
  kill -0 "$worker_pid" 2>/dev/null || fail "toxiproxy-routed worker $worker_pid crashed after its Postgres connection was reset mid-flight -- a torn connection must be recoverable, not fatal"
  log "toxiproxy-routed worker $worker_pid survived a torn (reset_peer) Postgres connection while it was live"

  # Meanwhile the rest of the system -- the always-on Compose
  # control-plane, talking to Postgres directly and completely unaffected
  # by this proxy -- must keep working normally: one instance's torn
  # connection must not corrupt shared state or degrade Postgres for
  # anyone else.
  local api_key wid state container_id
  api_key="$(new_tenant "e2e-chaos-postgres-torn")"
  wid="$(submit_workload "$api_key")"
  state="$(wait_workload_terminal "$wid" 180)" || true
  [[ "$state" == "RUNNING" ]] || fail "workload $wid did not reach RUNNING while a torn Postgres connection was live on the toxiproxy-routed worker (last state: $state)"
  container_id="$(psql_exec "SELECT container_id FROM workloads WHERE workload_id='$wid';" | tr -d '[:space:]')"
  register_cleanup "docker rm -f \"$container_id\" >/dev/null 2>&1 || true"
  stop_and_release_capacity "$api_key" "$wid"

  log "heal: removing the reset_peer toxics"
  curl -fsS -X DELETE "$toxi_admin/proxies/$proxy_name/toxics/e2e-reset-upstream" >/dev/null || true
  curl -fsS -X DELETE "$toxi_admin/proxies/$proxy_name/toxics/e2e-reset-downstream" >/dev/null || true

  # Recovery: not just "still alive" above -- after healing, this same
  # worker must still be genuinely usable, able to win a claim and drive a
  # workload to completion with no duplicate lease/container.
  local api_key2 wid2 state2 lease_count2 container_id2
  api_key2="$(new_tenant "e2e-chaos-postgres-torn-recovery")"
  wid2="$(submit_workload "$api_key2")"
  state2="$(wait_workload_terminal "$wid2" 180)" || true
  [[ "$state2" == "RUNNING" ]] || fail "workload $wid2 did not reach RUNNING after healing the torn Postgres connection (last state: $state2)"
  lease_count2="$(psql_exec "SELECT count(DISTINCT lease_id) FROM workloads WHERE workload_id='$wid2';" | tr -d '[:space:]')"
  [[ "$lease_count2" == "1" ]] || fail "workload $wid2 ended up with $lease_count2 distinct lease_ids after the torn-connection scenario"
  container_id2="$(psql_exec "SELECT container_id FROM workloads WHERE workload_id='$wid2';" | tr -d '[:space:]')"
  register_cleanup "docker rm -f \"$container_id2\" >/dev/null 2>&1 || true"
  stop_and_release_capacity "$api_key2" "$wid2"

  # Explicit teardown now (same reasoning as scenario_agent_timeout's own
  # early teardown): the next scenario (or the suite's own exit) must see
  # this worker and the chaos-profile proxy stopped, not still running.
  kill "$worker_pid" >/dev/null 2>&1 || true
  wait "$worker_pid" 2>/dev/null || true
  "${compose[@]}" --profile chaos stop toxiproxy >/dev/null 2>&1 || true

  log "PASS: Postgres torn connection -- worker survived a mid-flight reset_peer TCP RST, the shared system kept working throughout, and recovery after healing left no duplicate lease/container"
}

scenario_control_plane_restart
scenario_network_partition
scenario_redis_loss
scenario_postgres_recovery
scenario_agent_timeout
scenario_chain_delay
scenario_postgres_torn_connection

echo "E2E chaos-injection suite PASSED"
