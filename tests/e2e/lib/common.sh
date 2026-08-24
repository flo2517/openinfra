#!/usr/bin/env bash
# Shared fixtures, cleanup, and wait helpers for every tests/e2e/suites/*.sh
# script. Sourced, never executed directly -- every suite starts with:
#
#   repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
#   export E2E_REPO_ROOT="$repo_root"
#   # shellcheck source=tests/e2e/lib/common.sh
#   . "$repo_root/tests/e2e/lib/common.sh"
#
# Design constraints this file exists to enforce uniformly, per
# tests/AGENTS.md ("isolate fixtures, enforce timeouts, and clean all
# resources automatically"):
#   - every resource a suite creates gets a run-unique name/suffix, so two
#     suites (or two runs of the same suite) never collide;
#   - every cleanup is registered the moment the resource is known to
#     exist, not written once at the bottom of the script -- a failure
#     halfway through must not skip cleanup for what was already created;
#   - cleanup runs on EXIT regardless of pass/fail (set -e + trap), in
#     reverse registration order, and never lets one failed cleanup step
#     abort the rest.
set -euo pipefail

if [[ -z "${E2E_REPO_ROOT:-}" ]]; then
  echo "common.sh: E2E_REPO_ROOT must be set by the sourcing script" >&2
  exit 1
fi
repo_root="$E2E_REPO_ROOT"

compose=(docker compose --env-file "$repo_root/.env" -f "$repo_root/deployments/docker-compose.yml")

set -a
# shellcheck disable=SC1091
. "$repo_root/.env"
set +a

# run_id: unique per invocation of the *dispatcher* (run.sh exports it so
# every suite in one `make e2e` run shares it and their resource names
# don't collide with a concurrent or previous run); a suite invoked
# standalone falls back to generating its own.
run_id="${E2E_RUN_ID:-$(date +%s)-$$}"
export E2E_RUN_ID="$run_id"

suite_name="$(basename "${BASH_SOURCE[1]:-suite}" .sh)"

log() {
  printf '[%s] %s\n' "$suite_name" "$*"
}

fail() {
  printf '[%s] FAIL: %s\n' "$suite_name" "$*" >&2
  exit 1
}

# --- cleanup stack -------------------------------------------------------
# Bash has no closures, so each registration is a literal command string
# eval'd at cleanup time -- callers must single-quote anything that should
# be expanded lazily (e.g. 'rm -rf "$some_dir"' with $some_dir set by the
# time cleanup runs, not at registration time) and double-quote/expand
# anything that must be captured now.
#
# Backed by a file, not an in-memory array: `provider_id="$(start_provider_
# agent ...)"` (lib.sh's own fixture builders, called this way from every
# suite) runs the whole function in a command-substitution *subshell* --
# any register_cleanup call made inside it would append to a copy of an
# in-memory array that vanishes when the subshell exits, silently losing
# that cleanup. Confirmed live: this was a real, present bug (every
# start_provider_agent/start_extra_controlplane_worker cleanup was being
# dropped this way) until this file-based rewrite. A plain file's writes
# are visible to the parent shell the instant the subshell's `>>` returns,
# with no such gap.
_cleanup_log="$(mktemp)"

register_cleanup() {
  echo "$1" >>"$_cleanup_log"
}

run_cleanups() {
  local cmd
  # mapfile slurps every line up front, not `while read ... done < <(tac
  # ...)`: a cleanup command that itself reads stdin (docker compose exec
  # -T still leaves stdin connected, only TTY allocation is disabled) would
  # otherwise silently steal input from the loop's own process
  # substitution and truncate it after whichever line that command
  # happened to run on -- confirmed live, exactly this way: cleanup was
  # observed processing only the last 2 of 10 registered entries, always
  # stopping right after the first `psql_exec` (docker compose exec)
  # call consumed the rest of the pipe.
  local -a cmds=()
  if [[ -s "$_cleanup_log" ]]; then
    mapfile -t cmds < <(tac "$_cleanup_log")
  fi
  if [[ "${#cmds[@]}" -gt 0 ]]; then
    for cmd in "${cmds[@]}"; do
      [[ -z "$cmd" ]] && continue
      log "cleanup: $cmd"
      eval "$cmd" </dev/null || log "cleanup step failed (continuing): $cmd"
    done
  fi
  rm -f "$_cleanup_log" 2>/dev/null || true
}

trap run_cleanups EXIT

# --- compose/db/redis helpers ---------------------------------------------

psql_exec() {
  # psql_exec <sql>  -- runs against the compose Postgres as POSTGRES_USER/DB.
  "${compose[@]}" exec -T postgres sh -c \
    "psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -v ON_ERROR_STOP=1 -tA -c \"$1\""
}

psql_exec_db() {
  # psql_exec_db <database> <sql> -- same, against an explicit database
  # name rather than $POSTGRES_DB (used by the migrations-rollback suite's
  # scratch database).
  local db="$1" sql="$2"
  "${compose[@]}" exec -T postgres sh -c \
    "psql -U \"\$POSTGRES_USER\" -d \"$db\" -v ON_ERROR_STOP=1 -tA -c \"$sql\""
}

redis_exec() {
  "${compose[@]}" exec -T redis redis-cli "$@"
}

service_container_id() {
  "${compose[@]}" ps -q "$1" 2>/dev/null
}

# wait_service_healthy <service> [timeout_s] -- polls Docker's own health
# status for a service with a healthcheck (deployments/docker-compose.yml
# defines one for every service these suites touch), falling back to
# "container is running" for one that doesn't.
wait_service_healthy() {
  local svc="$1" timeout_s="${2:-60}" waited=0 cid status
  while (( waited < timeout_s )); do
    cid="$(service_container_id "$svc")"
    if [[ -n "$cid" ]]; then
      status="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
      [[ "$status" == "healthy" || "$status" == "running" ]] && return 0
    fi
    sleep 3
    waited=$((waited + 3))
  done
  return 1
}

require_stack_up() {
  local svc
  for svc in "$@"; do
    "${compose[@]}" ps --status running --services | grep -qx "$svc" \
      || fail "$svc is not running -- run 'make dev-up' first"
  done
}

# wait_until <timeout_s> <interval_s> <description> -- <command...>
# Retries <command...> (a full argv, not a string -- avoids an eval) until
# it exits 0 or the timeout elapses. Every polling loop in these suites
# goes through this helper so no suite hand-rolls its own retry/sleep and
# silently forgets a bound.
wait_until() {
  local timeout_s="$1" interval_s="$2" description="$3"
  shift 3
  local waited=0
  while (( waited < timeout_s )); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$interval_s"
    waited=$((waited + interval_s))
  done
  log "timed out after ${timeout_s}s waiting for: $description"
  return 1
}

unique_suffix() {
  # Short, filesystem/SQL-identifier-safe, unique within one run_id.
  printf '%s-%s' "$run_id" "$RANDOM"
}

heartbeat_ttl_positive() {
  # heartbeat_ttl_positive <provider_id> -- exit 0 iff Redis has a live
  # (TTL > 0) heartbeat cache entry for the provider. Argv form so it
  # plugs directly into wait_until without an inner eval/bash -c (a
  # `bash -c` there would run in a fresh process that never inherited
  # this shell's functions in the first place).
  local provider_id="$1" ttl
  ttl="$(redis_exec PTTL "openinfra:heartbeat:$provider_id" 2>/dev/null | tr -d '\r')"
  [[ "$ttl" =~ ^[0-9]+$ ]] && (( ttl > 0 ))
}

heartbeat_ttl_expired() {
  ! heartbeat_ttl_positive "$1"
}

# workload_state <workload_id> -- the authoritative Postgres state string
# for a workload (never trust a cached/derived value -- AGENTS.md).
workload_state() {
  psql_exec "SELECT state FROM workloads WHERE workload_id='$1';" | tr -d '[:space:]'
}

workload_state_is() {
  [[ "$(workload_state "$1")" == "$2" ]]
}

workload_state_is_not() {
  [[ "$(workload_state "$1")" != "$2" ]]
}

# --- shared binaries -------------------------------------------------------

build_shared_binaries() {
  local bin_dir="$1"
  log "building agent-cli, workloadctl, controlplane-admin, controlplane into $bin_dir"
  cargo build --quiet --manifest-path "$repo_root/provider-agent/Cargo.toml" -p agent-cli
  install -m 0755 "$repo_root/provider-agent/target/debug/agent-cli" "$bin_dir/agent-cli"
  go build -C "$repo_root/control-plane" -o "$bin_dir/workloadctl" ./cmd/workloadctl
  go build -C "$repo_root/control-plane" -o "$bin_dir/controlplane-admin" ./cmd/controlplane-admin
  go build -C "$repo_root/control-plane" -o "$bin_dir/controlplane" ./cmd/controlplane
}

# ensure_shared_binaries -- lazy, not automatic at source time. Building
# agent-cli (a full `cargo build`) plus three `go build`s is real, non-free
# cost that a suite with no Provider Agent / Control Plane binary
# dependency (30-migrations-rollback: Postgres and a bash/awk ROLLBACK.md
# parser only) has no reason to pay -- this is exactly the "no Substrate/
# provider-agent dependency, only Postgres" property issue #139's CI-wiring
# item relies on to keep that one suite cheap enough for a shared runner.
# Every suite that actually touches $E2E_BIN_DIR (00/10/20, today) must
# call this itself, right after sourcing this file. Built once by run.sh
# (the dispatcher) into $E2E_BIN_DIR and reused by every suite it spawns
# that needs it (run.sh pre-builds only when at least one requested suite
# calls this, see run.sh); a suite run standalone
# (./suites/00-happy-path.sh) builds its own into a throwaway dir instead
# so it stays runnable in isolation. Idempotent: a second call in the same
# process (or a child that inherited $E2E_BIN_DIR from run.sh) is a no-op.
ensure_shared_binaries() {
  if [[ -z "${E2E_BIN_DIR:-}" ]]; then
    E2E_BIN_DIR="$(mktemp -d)"
    export E2E_BIN_DIR
    register_cleanup "rm -rf \"$E2E_BIN_DIR\""
    build_shared_binaries "$E2E_BIN_DIR"
  fi
}

# agent_client_tls_env / agent_server_tls_env echo `export` lines for the
# mTLS identities suites need; sourced with `eval "$(agent_client_tls_env)"`
# rather than duplicated as literal `export FOO=...` blocks in each suite.
agent_client_tls_env() {
  cat <<EOF
export TLS_CERT_FILE="$repo_root/deployments/local/certs/client.crt"
export TLS_KEY_FILE="$repo_root/deployments/local/certs/client.key"
export TLS_CA_FILE="$repo_root/deployments/local/certs/ca.crt"
export TLS_SERVER_NAME=control-plane
EOF
}

agent_server_tls_env() {
  cat <<EOF
export AGENT_TLS_CERT_FILE="$repo_root/deployments/local/certs/agent-server.crt"
export AGENT_TLS_KEY_FILE="$repo_root/deployments/local/certs/agent-server.key"
export AGENT_TLS_CLIENT_CA_FILE="$repo_root/deployments/local/certs/ca.crt"
EOF
}

# Applied once, right here, for every suite process -- not just left for
# each suite (or start_provider_agent) to `eval` for itself. `.env`
# itself sets TLS_CERT_FILE et al. as *relative* paths (documented as
# relative to control-plane/, for a developer running agent-cli by hand
# from there); this file's own `set -a; . "$repo_root/.env"; set +a`
# above loads that relative form verbatim. Confirmed live: any call site
# that only ever set the absolute form *inside* a `$(some_function ...)`
# command substitution (start_provider_agent used to be the only place
# that did) never actually fixed it for the rest of the suite -- exports
# made inside a command-substitution subshell do not propagate back to
# the parent shell, so workloadctl/controlplane-admin calls made later at
# the suite's own top level (every submission in
# 10-multi-provider-concurrency.sh, every helper in
# 20-chaos-injection.sh) kept using the stale relative path and failed
# outright ("open ../deployments/local/certs/client.crt: no such file or
# directory") unless the current directory happened to be control-plane/.
# Setting it once here, unconditionally, at this file's own top level
# (never inside a subshell), means every suite gets the correct absolute
# paths from the moment it finishes sourcing this file, with nothing
# further for any suite to remember.
eval "$(agent_client_tls_env)"

# start_provider_agent <work_dir> <listen_port> -- inits and starts a full
# `agent-cli start` daemon (background heartbeat + live mTLS gRPC server),
# registers its cleanup (kill the process, remove Postgres/Redis rows and
# the temp dir), and leaves $work_dir/start.log for debugging. Echoes the
# joined provider_id on success, returns non-zero on failure (join
# timeout/rejection) -- callers must check the exit code, not just look
# for empty output.
# agent_join_with_retry <work_dir> -- runs `agent-cli join` from within
# work_dir, retrying up to 3 times (each attempt capped at 40s) and
# echoing the command's stdout on success. Every caller that runs
# `agent-cli join` in this suite matrix goes through this, not just
# start_provider_agent below: CompleteJoin's client-side gRPC deadline is
# hardcoded at 30s in agent-cli itself (crates/agent-cli/src/main.rs,
# complete_request.set_timeout) -- a wrapper `timeout` longer than that
# changes nothing about when the *client* gives up. Every provider join
# (and every lease, offer-announce, and Network Validator evidence
# submission -- all real, ongoing background traffic once more than one
# provider/validator exists in the stack, PR #135) signs with the same
# bridge/sudo account (SUBSTRATE_SIGNER_KEY_FILE), so extrinsics queue
# behind each other on a strictly sequential nonce; *any* join, including
# the first in a run, can see its own finality wait pushed past 30s by
# that queue even though the RPC call itself is healthy -- confirmed live
# while developing this suite matrix, worse than the phenomenon tests/e2e/
# run.sh's pre-restructure comment on this exact call already documented
# for a second provider specifically (that comment predates PR #135's
# Network Validators and market-offer reconciler, both additional,
# continuous sources of contention on the same one nonce). A retried join
# is safe: BeginJoin mints a fresh challenge each time, and CompleteJoin
# against an already-finalized registration is the same idempotent-replay
# path ReportHeartbeat already relies on.
agent_join_with_retry() {
  local work_dir="$1" join_output attempt
  for attempt in 1 2 3 4 5; do
    if join_output="$(cd "$work_dir" && timeout 40s "$E2E_BIN_DIR/agent-cli" join)"; then
      echo "$join_output"
      return 0
    fi
    log "agent join attempt $attempt/5 in $work_dir failed or timed out: ${join_output:-<none>}"
    # 20s, not a token pause: a client-side timeout here does not mean
    # nothing was submitted -- providerjoin.Service's own EnsureActive
    # can still be finalizing server-side after agent-cli's client gives
    # up (its own CompleteJoin deadline is a hard 30s), leaving the
    # provider row in READY. internal/providerjoin's background
    # Reconciler (main.go: `go reconciler.Run(ctx)`) polls READY/RETRY
    # rows every 15s (DefaultReconcilerConfig) and finishes activating
    # them on its own -- but an *immediate* retry races a fresh
    # CompleteJoin for the same deterministic provider_id against that
    # in-flight reconcile, and the loser gets a genuine Postgres
    # serialization failure (SQLSTATE 40001, confirmed live). Waiting out
    # one full reconciler interval first means the retry's own
    # CompleteJoin usually finds status already ACTIVE and returns
    # immediately, without touching the chain or Postgres's write path a
    # second time at all.
    sleep 20
  done
  return 1
}

start_provider_agent() {
  local work_dir="$1" listen_port="$2"
  mkdir -p "$work_dir"
  register_cleanup "rm -rf \"$work_dir\""
  (
    cd "$work_dir"
    "$E2E_BIN_DIR/agent-cli" init >/dev/null
    sed -i "s/^  listen_address: .*/  listen_address: 0.0.0.0:${listen_port}/" config.yaml
    sed -i "s#^  advertised_endpoint: ''#  advertised_endpoint: https://host.docker.internal:${listen_port}#" config.yaml
  )

  local join_output provider_id
  eval "$(agent_client_tls_env)"
  if ! join_output="$(agent_join_with_retry "$work_dir")"; then
    log "agent join in $work_dir did not succeed after 5 attempts"
    return 1
  fi
  provider_id="$(sed -n 's/^Provider ACTIVE: //p' <<<"$join_output")"
  if [[ ! "$provider_id" =~ ^[0-9a-f]{64}$ ]]; then
    log "agent in $work_dir did not report a valid provider_id"
    return 1
  fi
  register_cleanup "redis_exec DEL \"openinfra:heartbeat:$provider_id\" >/dev/null 2>&1 || true"
  register_cleanup "psql_exec \"DELETE FROM provider_chain_registrations WHERE provider_id='$provider_id'; DELETE FROM provider_join_completions WHERE provider_id='$provider_id'; DELETE FROM provider_join_challenges WHERE provider_id='$provider_id'; DELETE FROM providers WHERE provider_id='$provider_id';\" >/dev/null 2>&1 || true"

  eval "$(agent_server_tls_env)"
  # `exec` here, not `cd ... && agent-cli start`: without it, bash forks a
  # subshell process to run this pipeline and $! below would be *that*
  # subshell's pid, not agent-cli's -- kill $! would then have nothing to
  # actually propagate the signal to agent-cli, leaking it as an orphan.
  # `exec` replaces the subshell's own process image with agent-cli, so
  # $! is agent-cli's real pid and `kill $!` reaches it directly.
  ( cd "$work_dir" || exit 1
    exec "$E2E_BIN_DIR/agent-cli" start >"$work_dir/start.log" 2>&1
  ) &
  local agent_pid=$!
  register_cleanup "kill $agent_pid >/dev/null 2>&1 || true; wait $agent_pid 2>/dev/null || true"

  if ! wait_until 15 1 "heartbeat TTL for $provider_id" heartbeat_ttl_positive "$provider_id"; then
    log "agent in $work_dir never reported a live heartbeat"
    return 1
  fi

  echo "$provider_id"
}

# start_extra_controlplane_worker <work_dir> <grpc_port> <http_port>
#   [database_url_override] --
# runs a second (third, ...) `controlplane` process against the same
# Postgres/Redis/Substrate the Compose control-plane service already uses,
# the same way a horizontally-scaled deployment would: each instance gets
# its own random orchestrator.Worker workerID (uuid, generated in
# NewWorker) and races the others for workload claims via the
# version+worker_lease_until optimistic lock in
# internal/workloadapi/postgres.go. Not reachable by any client in this
# suite -- it exists purely to prove concurrent claiming is safe, so its
# own gRPC/HTTP ports are never dialed.
#
# database_url_override (optional, 4th arg): when set, used as this one
# instance's DATABASE_URL instead of the normal compose-network
# connection string -- 20-chaos-injection.sh's torn-connection scenario
# passes a connection string through the "chaos"-profile toxiproxy proxy
# (deployments/docker-compose.yml) so this specific worker's Postgres
# traffic, and only this worker's, can have a real TCP RST injected into
# it mid-flight without touching the default stack's own control-plane.
start_extra_controlplane_worker() {
  local work_dir="$1" grpc_port="$2" http_port="$3" database_url_override="${4:-}"
  mkdir -p "$work_dir"
  register_cleanup "rm -rf \"$work_dir\""
  # See start_provider_agent's comment on why this is `exec`'d: without
  # it, $! below would name a subshell wrapping controlplane rather than
  # controlplane itself, and `kill $!` would leak it as an orphan.
  (
    export DATABASE_URL REDIS_URL SUBSTRATE_RPC_URL
    if [[ -n "$database_url_override" ]]; then
      export DATABASE_URL="$database_url_override"
    fi
    export SUBSTRATE_SIGNER_KEY_FILE="$repo_root/deployments/local/certs/bridge-key.pem"
    export CONTROL_PLANE_GRPC_ADDR="127.0.0.1:${grpc_port}"
    export CONTROL_PLANE_HTTP_ADDR="127.0.0.1:${http_port}"
    export TLS_CERT_FILE="$repo_root/deployments/local/certs/server.crt"
    export TLS_KEY_FILE="$repo_root/deployments/local/certs/server.key"
    export TLS_CLIENT_CA_FILE="$repo_root/deployments/local/certs/ca.crt"
    export AGENT_CLIENT_TLS_CERT_FILE="$repo_root/deployments/local/certs/client.crt"
    export AGENT_CLIENT_TLS_KEY_FILE="$repo_root/deployments/local/certs/client.key"
    export AGENT_CLIENT_TLS_CA_FILE="$repo_root/deployments/local/certs/ca.crt"
    exec "$E2E_BIN_DIR/controlplane" >"$work_dir/controlplane.log" 2>&1
  ) &
  local worker_pid=$!
  register_cleanup "kill $worker_pid >/dev/null 2>&1 || true; wait $worker_pid 2>/dev/null || true"

  wait_until 30 1 "extra control-plane worker in $work_dir ready" \
    grep -q "Control Plane gRPC listening" "$work_dir/controlplane.log" \
    || { log "extra control-plane worker in $work_dir never became ready:"; cat "$work_dir/controlplane.log" >&2 || true; return 1; }

  echo "$worker_pid"
}
