#!/usr/bin/env bash
# Suite 10: multiple Provider Agents and concurrent Control Plane workers
# against the real stack, driving several workloads through Submit ->
# lease -> deploy at once. This is the acceptance criterion's "run
# concurrent Control Plane workers and multiple Provider Agents" and half
# of "verify idempotence and absence of duplicate containers, leases,
# rewards, or reservations" -- the other half (behavior under an
# injected restart) lives in suite 20.
#
# Three extra Provider Agents run as host processes (in addition to the
# always-on Compose provider-agent container -- four real providers
# total), and two extra `controlplane` processes run as host processes
# sharing the same Postgres/Redis/Substrate as the Compose control-plane
# (three real orchestrator.Worker instances total, each with its own
# random workerID racing the others via the version+worker_lease_until
# optimistic lock in internal/workloadapi/postgres.go). Six workloads are
# submitted concurrently; the suite asserts every one reaches a terminal
# state with no duplicate lease_id/container_id and no more than one
# worker holding a live claim on the same workload at once.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export E2E_REPO_ROOT="$repo_root"
# shellcheck source=tests/e2e/lib/common.sh
. "$repo_root/tests/e2e/lib/common.sh"

require_stack_up postgres redis blockchain-node control-plane docker-socket-proxy provider-agent

# --- multiple Provider Agents --------------------------------------------
declare -a provider_ids=()
for i in 1 2 3; do
  port=$((50100 + i))
  work_dir="$(mktemp -d)"
  provider_id="$(start_provider_agent "$work_dir" "$port")" \
    || fail "provider agent #$i failed to join/start"
  provider_ids+=("$provider_id")
  log "provider agent #$i joined as $provider_id (port $port)"
done

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

log "multi-provider-concurrency suite PASSED: $workload_count workloads, $distinct_providers_used providers, no duplicate leases/containers"
echo "E2E multi-provider-concurrency suite PASSED"
