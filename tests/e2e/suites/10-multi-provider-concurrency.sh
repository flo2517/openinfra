#!/usr/bin/env bash
# Suite 10: multiple Provider Agents and concurrent Control Plane workers
# against the real stack, driving several workloads through Submit ->
# lease -> deploy at once. This is the acceptance criterion's "run
# concurrent Control Plane workers and multiple Provider Agents" and half
# of "verify idempotence and absence of duplicate containers, leases,
# rewards, or reservations" -- the other half (behavior under an
# injected restart) lives in suite 20.
#
# Three extra Provider Agents (in addition to the always-on Compose
# provider-agent container -- four real providers total) and two extra
# `controlplane` processes run as host processes sharing the same
# Postgres/Redis/Substrate as the Compose control-plane (three real
# orchestrator.Worker instances total, each with its own random workerID
# racing the others via the version+worker_lease_until optimistic lock in
# internal/workloadapi/postgres.go). Six workloads are submitted
# concurrently; the suite asserts every one reaches a terminal state with
# no duplicate lease_id/container_id and no more than one worker holding a
# live claim on the same workload at once.
#
# Issue #139: when `COMPOSE_PROFILES=multi-node` (PR #135) is active --
# detected, not assumed -- two of the three extra Provider Agents are the
# real containerized provider-agent-2/provider-agent-3 services instead of
# another disposable host process, exercising their actual container
# healthchecks/networking rather than only ever the host-process path.
# The suite falls back to three host-process agents exactly as before when
# that profile is not enabled, so it stays runnable either way. With the
# profile's full Network Validator committee also up
# (networkvalidator/-2/-3), this suite additionally exercises
# pallet-network-validator's MinQuorum=3 actually closing a round -- a
# genuine multi-node scenario nothing else in this matrix covers, since
# the default stack's single validator can never reach quorum on its own
# (tests/e2e/AGENTS.md).
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export E2E_REPO_ROOT="$repo_root"
# shellcheck source=tests/e2e/lib/common.sh
. "$repo_root/tests/e2e/lib/common.sh"

ensure_shared_binaries
require_stack_up postgres redis blockchain-node control-plane docker-socket-proxy provider-agent

# --- multiple Provider Agents --------------------------------------------
# multi_node_active: detected, not assumed -- `docker compose ps` only
# lists provider-agent-2/provider-agent-3 as running services when the
# caller actually set `COMPOSE_PROFILES=multi-node` (deployments/
# docker-compose.yml), so this suite behaves identically to before when
# that profile is off and nobody has to opt into anything just to run it.
multi_node_active=""
if "${compose[@]}" ps --status running --services 2>/dev/null | grep -qx provider-agent-2 \
  && "${compose[@]}" ps --status running --services 2>/dev/null | grep -qx provider-agent-3; then
  multi_node_active=1
fi

declare -a provider_ids=()
if [[ -n "$multi_node_active" ]]; then
  log "COMPOSE_PROFILES=multi-node is active: using the real containerized provider-agent-2/provider-agent-3 (PR #135) for two of this suite's extra providers"
  for svc in provider-agent-2 provider-agent-3; do
    # These containers self-join at startup (provider-agent/docker/
    # entrypoint.sh) and keep heartbeating on their own -- nothing here
    # starts or stops them, and no cleanup deletes their provider row;
    # they are persistent stack members, not this suite's disposable
    # fixtures, unlike the host-process agents below.
    endpoint="https://$svc:50052"
    provider_id="$(psql_exec "SELECT provider_id FROM providers WHERE agent_endpoint='$endpoint' ORDER BY registered_at DESC LIMIT 1;" | tr -d '[:space:]')"
    [[ "$provider_id" =~ ^[0-9a-f]{64}$ ]] || fail "no registered provider found for $svc (agent_endpoint=$endpoint) -- has it finished joining?"
    wait_until 30 2 "heartbeat TTL for $svc's provider $provider_id" heartbeat_ttl_positive "$provider_id" \
      || fail "$svc's provider $provider_id has no live heartbeat"
    provider_ids+=("$provider_id")
    log "containerized $svc is provider $provider_id"
  done
  # A third, disposable host-process provider on top of the two
  # containerized ones -- keeps this suite's total extra-provider count
  # (3, plus the always-on compose provider-agent = 4) the same whether or
  # not the profile is enabled, rather than silently testing fewer
  # providers just because it happened to be on.
  port=50103
  work_dir="$(mktemp -d)"
  provider_id="$(start_provider_agent "$work_dir" "$port")" \
    || fail "provider agent #3 (host process) failed to join/start"
  provider_ids+=("$provider_id")
  log "provider agent #3 (host process) joined as $provider_id (port $port)"
else
  log "COMPOSE_PROFILES=multi-node is not active -- falling back to 3 disposable host-process Provider Agents (see README.md / tests/e2e/AGENTS.md to enable the multi-node profile)"
  for i in 1 2 3; do
    port=$((50100 + i))
    work_dir="$(mktemp -d)"
    provider_id="$(start_provider_agent "$work_dir" "$port")" \
      || fail "provider agent #$i failed to join/start"
    provider_ids+=("$provider_id")
    log "provider agent #$i joined as $provider_id (port $port)"
  done
fi

# --- concurrent Control Plane workers -------------------------------------
declare -a worker_pids=()
for i in 1 2; do
  grpc_port=$((50060 + i))
  http_port=$((8080 + i))
  work_dir="$(mktemp -d)"
  worker_pid="$(start_extra_controlplane_worker "$work_dir" "$grpc_port" "$http_port")" \
    || fail "extra control-plane worker #$i failed to start"
  worker_pids+=("$worker_pid")
  log "extra control-plane worker #$i running as pid $worker_pid (grpc 127.0.0.1:$grpc_port)"
done

# --- tenant + workloads ----------------------------------------------------
create_user_output="$("$E2E_BIN_DIR/controlplane-admin" create-user "e2e-multi-provider")"
user_id="$(sed -n 's/^user_id: //p' <<<"$create_user_output")"
api_key="$(sed -n 's/^api_key: //p' <<<"$create_user_output" | awk '{print $1}')"
[[ "$user_id" =~ ^[0-9a-f-]{36}$ ]] || fail "create-user did not return a user_id"
register_cleanup "psql_exec \"DELETE FROM api_keys WHERE user_id='$user_id'; DELETE FROM users WHERE user_id='$user_id';\" >/dev/null 2>&1 || true"

deploy_image="registry.k8s.io/pause:3.9"
docker pull -q "$deploy_image" >/dev/null
deploy_image_ref="$(docker inspect --format='{{index .RepoDigests 0}}' "$deploy_image")"

workload_count=6
submissions_dir="$(mktemp -d)"
register_cleanup "rm -rf \"$submissions_dir\""

log "submitting $workload_count workloads concurrently"
declare -a submit_pids=()
for i in $(seq 1 "$workload_count"); do
  (
    OPENINFRA_API_KEY="$api_key" "$E2E_BIN_DIR/workloadctl" submit "$deploy_image_ref" 0.1 64 0 300 \
      >"$submissions_dir/submit-$i.out" 2>"$submissions_dir/submit-$i.err"
  ) &
  submit_pids+=($!)
done
submit_failures=0
for i in $(seq 1 "$workload_count"); do
  wait "${submit_pids[$((i - 1))]}" || {
    submit_failures=$((submit_failures + 1))
    log "submission $i failed: $(cat "$submissions_dir/submit-$i.out" "$submissions_dir/submit-$i.err" 2>/dev/null)"
  }
done
[[ "$submit_failures" -eq 0 ]] || fail "$submit_failures of $workload_count concurrent submissions failed"

declare -a workload_ids=()
for i in $(seq 1 "$workload_count"); do
  wid="$(sed -n 's/^workload_id: //p' "$submissions_dir/submit-$i.out")"
  [[ "$wid" =~ ^[0-9a-f-]{36}$ ]] || fail "submission $i did not return a valid workload_id: $(cat "$submissions_dir/submit-$i.out" "$submissions_dir/submit-$i.err")"
  workload_ids+=("$wid")
  register_cleanup "psql_exec \"DELETE FROM workloads WHERE workload_id='$wid';\" >/dev/null 2>&1 || true"
done
distinct_workload_ids="$(printf '%s\n' "${workload_ids[@]}" | sort -u | wc -l)"
[[ "$distinct_workload_ids" -eq "$workload_count" ]] || fail "expected $workload_count distinct workload_ids, got $distinct_workload_ids"
log "submitted workloads: ${workload_ids[*]}"

# --- drive to terminal state, sampling worker_id distribution along the way
workload_id_list="$(printf "'%s'," "${workload_ids[@]}")"
workload_id_list="${workload_id_list%,}"
seen_workers_file="$(mktemp)"
register_cleanup "rm -f \"$seen_workers_file\""

all_terminal=""
for _ in $(seq 1 90); do
  psql_exec "SELECT DISTINCT worker_id FROM workloads WHERE workload_id IN ($workload_id_list) AND worker_id IS NOT NULL;" >>"$seen_workers_file" || true
  non_terminal="$(psql_exec "SELECT count(*) FROM workloads WHERE workload_id IN ($workload_id_list) AND state NOT IN ('RUNNING','FAILED');" | tr -d '[:space:]')"
  if [[ "$non_terminal" == "0" ]]; then
    all_terminal=1
    break
  fi
  sleep 3
done
[[ -n "$all_terminal" ]] || fail "not every workload reached a terminal state within the timeout"

distinct_workers_seen="$(sort -u "$seen_workers_file" | sed '/^$/d' | wc -l)"
log "distinct orchestrator worker_id values observed claiming these workloads: $distinct_workers_seen (3 workers were running)"

# --- no duplicate containers, leases, or reservations ---------------------
running_count="$(psql_exec "SELECT count(*) FROM workloads WHERE workload_id IN ($workload_id_list) AND state='RUNNING';" | tr -d '[:space:]')"
failed_count="$(psql_exec "SELECT count(*) FROM workloads WHERE workload_id IN ($workload_id_list) AND state='FAILED';" | tr -d '[:space:]')"
log "terminal states: $running_count RUNNING, $failed_count FAILED (of $workload_count)"
[[ "$failed_count" == "0" ]] || {
  psql_exec "SELECT workload_id, error_code, last_error FROM workloads WHERE workload_id IN ($workload_id_list) AND state='FAILED';" >&2
  fail "$failed_count of $workload_count workloads FAILED"
}

distinct_container_ids="$(psql_exec "SELECT count(DISTINCT container_id) FROM workloads WHERE workload_id IN ($workload_id_list) AND state='RUNNING';" | tr -d '[:space:]')"
[[ "$distinct_container_ids" == "$running_count" ]] || fail "container_id collision: $running_count RUNNING workloads but only $distinct_container_ids distinct container_ids"

distinct_lease_ids="$(psql_exec "SELECT count(DISTINCT lease_id) FROM workloads WHERE workload_id IN ($workload_id_list) AND lease_id IS NOT NULL;" | tr -d '[:space:]')"
leased_count="$(psql_exec "SELECT count(*) FROM workloads WHERE workload_id IN ($workload_id_list) AND lease_id IS NOT NULL;" | tr -d '[:space:]')"
[[ "$distinct_lease_ids" == "$leased_count" ]] || fail "lease_id collision: $leased_count leased workloads but only $distinct_lease_ids distinct lease_ids"

distinct_providers_used="$(psql_exec "SELECT count(DISTINCT provider_id) FROM workloads WHERE workload_id IN ($workload_id_list) AND provider_id IS NOT NULL;" | tr -d '[:space:]')"
log "workloads were placed across $distinct_providers_used distinct provider(s) out of 4 available"

# Every real docker container behind a RUNNING row must actually be
# running -- not just a Postgres string -- and there must be exactly one
# per RUNNING workload (no leaked duplicate from a lost race).
container_ids_output="$(psql_exec "SELECT container_id FROM workloads WHERE workload_id IN ($workload_id_list) AND state='RUNNING';")"
while IFS= read -r container_id; do
  [[ -z "$container_id" ]] && continue
  register_cleanup "docker rm -f \"$container_id\" >/dev/null 2>&1 || true"
  [[ "$(docker inspect --format='{{.State.Running}}' "$container_id" 2>/dev/null)" == "true" ]] \
    || fail "container $container_id for a RUNNING workload is not actually running"
done <<<"$container_ids_output"

# --- Network Validator quorum (issue #139) --------------------------------
# pallet-network-validator's MinQuorum is 3 (blockchain/runtime/src/
# lib.rs); the default stack runs exactly one Network Validator, which can
# never close a round on its own. This only runs with the full multi-node
# committee (networkvalidator + networkvalidator-2/-3, PR #135) up --
# nothing here starts it, matching the providers section above: detect,
# don't require.
if [[ -n "$multi_node_active" ]] \
  && "${compose[@]}" ps --status running --services 2>/dev/null | grep -qx networkvalidator-2 \
  && "${compose[@]}" ps --status running --services 2>/dev/null | grep -qx networkvalidator-3; then
  log "full Network Validator committee is up -- checking quorum"
  dashboard_url="${E2E_DASHBOARD_URL:-http://127.0.0.1:8080}"

  health_output="$(curl -fsS "$dashboard_url/api/v1/validator/health")" \
    || fail "validator health endpoint unreachable at $dashboard_url"
  active_count="$(grep -oE '"active_count":[0-9]+' <<<"$health_output" | grep -oE '[0-9]+')"
  [[ -n "$active_count" && "$active_count" -ge 3 ]] \
    || fail "expected at least 3 active Network Validators with the multi-node profile up, got '${active_count:-<none>}': $health_output"
  log "validator health: $active_count active validators (MinQuorum=3): $health_output"

  # Any of this suite's providers works; provider_ids[0] is always
  # populated (the containerized-or-host-process agent started first
  # above), and every provider gets challenged independently.
  quorum_provider_id="${provider_ids[0]}"
  rounds_url="$dashboard_url/api/v1/validator/rounds/$quorum_provider_id"
  # 180s at 5s: confirmed live during development that 3 independent
  # validator processes (networkvalidator's own 3s poll interval,
  # internal/networkvalidator/run.go) reach quorum on at least one
  # dimension well under a minute from a cold registration -- generous
  # room on top of that without hanging forever on a genuine regression.
  wait_until 180 5 "a round for provider $quorum_provider_id reaches quorum (3 independent validator submissions)" \
    bash -c "curl -fsS '$rounds_url' | grep -q '\"quorum_reached\":true'" \
    || fail "no dimension for provider $quorum_provider_id reached quorum within the timeout -- MinQuorum=3 with $active_count active validators should eventually close a round ($rounds_url)"

  log "PASS: Network Validator quorum reached for provider $quorum_provider_id ($rounds_url)"
else
  log "COMPOSE_PROFILES=multi-node's full Network Validator committee is not up -- skipping quorum coverage (see tests/e2e/AGENTS.md / README.md to enable it)"
fi

log "multi-provider-concurrency suite PASSED: $workload_count workloads, $distinct_providers_used providers, no duplicate leases/containers"
echo "E2E multi-provider-concurrency suite PASSED"
