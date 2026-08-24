# tests/e2e — Suite Guidelines

This directory is a matrix of independent E2E suites (issue #17) driven against
the real Compose stack (`deployments/docker-compose.yml`) -- real Postgres,
real Redis, a real Substrate dev chain, a real Control Plane, real Provider
Agents, real Docker containers. No suite here mocks a dependency; if a
dependency is unavailable the suite fails loudly (`require_stack_up` in
`lib/common.sh`), it never falls back to a stub.

## Layout

- `lib/common.sh` -- sourced, never executed. Shared fixtures/cleanup/wait
  helpers every suite uses: the cleanup stack (`register_cleanup`,
  `run_cleanups`, trapped on `EXIT`), Postgres/Redis helpers (`psql_exec`,
  `redis_exec`), `wait_until`/`wait_service_healthy` polling helpers, shared
  binary builds (`agent-cli`, `workloadctl`, `controlplane-admin`,
  `controlplane`), and fixture builders (`start_provider_agent`,
  `start_extra_controlplane_worker`).
- `suites/NN-name.sh` -- one independent, self-contained suite per file,
  numbered for a stable run order (`run.sh` with no arguments runs them in
  filename order). Each suite:
  - sources `lib/common.sh` first thing, after resolving its own
    `E2E_REPO_ROOT`;
  - calls `require_stack_up` for the Compose services it needs;
  - registers every cleanup step (`register_cleanup`) at the moment a
    resource is known to exist, not batched at the end -- a suite that
    fails halfway through still cleans up what it already created;
  - never touches another suite's fixtures; suite ordering matters only for
    total wall-clock time, not correctness (each suite tears down fully via
    its own `trap ... EXIT` before the next one starts, since `run.sh` runs
    them as separate `bash` processes in sequence, not in parallel);
  - is bounded by `run.sh`'s per-suite `timeout` wrapper (default 1800s,
    override with `E2E_SUITE_TIMEOUT_SECONDS`) on top of its own internal
    polling timeouts.
- `run.sh` -- the dispatcher. `make e2e` calls this with no arguments (every
  suite, in order, stopping at the first failure). Run a subset for local
  iteration: `tests/e2e/run.sh 00-happy-path` or
  `tests/e2e/run.sh 00-happy-path 30-migrations-rollback`.

## Suites

| Suite | Covers |
|---|---|
| `00-happy-path.sh` | The full target lifecycle: Join -> ACTIVE -> offer -> lease -> deploy -> observe -> stop -> reward, dashboard RBAC/tenant isolation, and a stop-replay idempotence check. |
| `10-multi-provider-concurrency.sh` | Three extra host-run Provider Agents (plus the always-on Compose one) and two extra `controlplane` worker processes sharing one Postgres/Redis/chain, driving six workloads submitted concurrently; asserts no duplicate lease_id/container_id and that real containers back every RUNNING row. |
| `20-chaos-injection.sh` | Six chaos scenarios against the real stack: control-plane restart, a CP<->Agent network partition, Redis loss, PostgreSQL recovery, an Agent timeout (process killed mid-deploy), and a chain delay (blockchain-node paused). Each restores the stack before the next scenario runs. Verification status: the first three (restart, network partition, Redis loss) passed cleanly, back to back, in a live run against the real stack; the fourth (PostgreSQL recovery) stalled on a post-recovery workload in one such run after ~7 minutes of continuous chaos (mTLS handshake errors against the Agent, cause not yet root-caused -- possibly this sandbox's resource limits under sustained churn rather than the scenario logic itself), so scenarios five and six were not exercised back-to-back with the rest in the same run. Cleanup was confirmed complete even on that failure (zero leaked processes, zero leaked provider rows) -- see the follow-up issue filed alongside this suite matrix. |
| `30-migrations-rollback.sh` | `control-plane/migrations/ROLLBACK.md` is complete (a section per migration file) and correct: forward-apply -> rollback -> forward-apply again reaches the same schema, against a disposable scratch database. |

## What is out of scope here, and why

- **A real multi-node consensus partition.** The dev chain is a single-node
  Aura+GRANDPA authority (ADR-009) -- there is no second validator to
  partition away from. `20-chaos-injection.sh`'s network-partition scenario
  covers the Control-Plane<->Agent link instead, which is the partition this
  system actually has today.
- **Torn/mid-write database or Redis failures.** `docker compose stop`
  sends a clean shutdown signal; forcing a genuinely torn write would need
  fault injection inside the DB/Redis engine itself (or a proxy like
  toxiproxy in front of it), which is a real, larger addition -- see the
  follow-up issue filed alongside this suite matrix.
- **CI.** None of these suites run in `.github/workflows/ci.yml`. They need
  the full Compose stack, including a from-source Substrate node build
  (`blockchain`'s own CI job budgets 60 minutes for that alone), multiple
  concurrent long-lived processes, and real container restarts/network
  manipulation -- none of which fits a shared, time-boxed CI runner without
  a meaningfully larger investment (a dedicated self-hosted runner or
  pre-baked images). `make e2e` (this directory) is the intended entry
  point for now, same as before this restructuring; wiring a subset into CI
  is tracked as a follow-up.
- **True idempotent-replay of `SubmitWorkload` at the E2E layer.**
  `workloadctl submit` always mints a fresh `request_id`/`workload_id`, so
  replaying the *exact same* request through the CLI isn't reachable from
  these suites. That idempotence (a repeated `request_id` returns the
  original workload rather than creating a second one) is unit-tested
  directly against the repository in
  `control-plane/internal/workloadapi/service_test.go`
  (`TestSubmitIsDurableAndIdempotent`). What these suites verify instead is
  idempotence *under real concurrency and real restarts* -- duplicate
  claims, duplicate leases, duplicate containers -- which a unit test
  cannot exercise.

## Gaps found -- and fixed -- while writing these suites

Three Provider Agent bugs, each confirmed live against the real Compose
stack and now fixed + unit-tested in this same change:

- `agent-executor`'s `stop()` stopped a container but never removed it
  (`provider-agent/crates/agent-executor/src/lib.rs`) -- every stopped
  workload leaked its container on the provider host forever.
- `agent-executor`'s `get_status()` returned a hard error for a workload
  record that exists but has no container yet, or whose container `stop()`
  had already removed -- both cases now report a clean `STATE_DEPLOYING`/
  `STATE_COMPLETED` instead. Before this fix, `internal/orchestrator/
  worker.go`'s reconcile-before-retry guard treated that error as "unknown,
  check again" and never re-attempted `Deploy`, so **any** transient
  failure on a workload's first deploy attempt permanently stranded it --
  this was the single biggest source of flakiness found this session.
- `BollardEngine::connect()` used `Docker::connect_with_local_defaults()`
  unconditionally, which silently ignores a `tcp://` `DOCKER_HOST` and
  falls back to a local unix socket path that does not exist in the
  Compose provider-agent container -- the always-on, default single-
  provider `make dev-up` stack could never actually deploy a workload
  through `docker-socket-proxy`. Now routes to `connect_with_http_defaults()`
  for a `tcp://`/`http://` `DOCKER_HOST`.

Two bugs in this suite matrix's own shared library, found while chasing
what first looked like environmental flakiness but wasn't:

- `register_cleanup` calls made inside `start_provider_agent`/
  `start_extra_controlplane_worker` were silently lost. Both are called as
  `"$(function ...)"` (command substitution), which runs the function body
  in a subshell -- an in-memory `_cleanup_stack` array populated inside
  that subshell vanishes when the subshell exits. Confirmed live: every
  suite run was leaking its disposable Provider Agent host processes and
  provider registrations, even on a full pass. `register_cleanup`/
  `run_cleanups` are now backed by a file (`_cleanup_log`), whose writes
  are visible across the subshell boundary the instant they happen.
- The cleanup replay loop was then found to be *truncating itself*:
  `while read ... done < <(tac "$_cleanup_log")` hands its process-
  substitution stdin to every command the loop body runs, and `docker
  compose exec` (used by `psql_exec`/`redis_exec`, most cleanup steps)
  reads from that same inherited stdin -- confirmed live, cleanup was
  processing only the last 2 of 10 registered steps, always stopping right
  after the first `psql_exec` call. Fixed by slurping the log into an
  array with `mapfile` first, then iterating a plain `for` loop.
- The same subshell issue affected `agent_client_tls_env`'s `export`s:
  `start_provider_agent` was the only call site that ever set the
  *absolute* mTLS cert paths, and it did so inside its own command-
  substitution subshell -- so `workloadctl`/`controlplane-admin` calls
  made later at a suite's own top level (every submission in
  `10-multi-provider-concurrency.sh`) kept using `.env`'s *relative*
  paths and failed outright unless the current directory happened to be
  `control-plane/`. Fixed by applying the absolute override once,
  unconditionally, at `lib/common.sh`'s own top level (never inside a
  subshell), so every suite gets it automatically.

**Still open** (Go-side, more invasive, deliberately not fixed here -- see
the follow-up issue filed alongside this suite matrix): both
`internal/orchestrator/worker.go`'s workload retry (`RetryLater`) and
`internal/resourcemarket/reconciler.go`'s offer-withdrawal retry have no
maximum attempt count or backoff -- a workload whose Agent has permanently
died, or a provider that has permanently vanished, retries every 5s/30s
forever rather than ever reaching a terminal state. `20-chaos-injection.sh`'s
`scenario_agent_timeout` asserts the safe property this system does
guarantee today (never falsely reports `RUNNING`, recovers cleanly once the
Agent comes back) rather than "reaches FAILED", which is still false.
Confirmed live: enough accumulated retry traffic from repeated E2E runs
that each left an orphaned provider behind produced a `1014: Priority is
too low` transaction pool collision that needed a Control Plane restart to
clear -- see the note below on cleaning that up if you hit it locally.

## A real characteristic of this stack worth knowing before you debug flakiness

Every on-chain write the Control Plane makes -- provider registration,
lease creation/completion, resource-market offer announce/withdraw, and
(once `COMPOSE_PROFILES=multi-node` is enabled) Network Validator
registration -- signs with the **same** bridge/sudo account
(`SUBSTRATE_SIGNER_KEY_FILE`), on a strictly sequential nonce. A single
provider join is normally fast, but a *second* join in the same run (as
`start_provider_agent` does in `00-happy-path.sh` and
`10-multi-provider-concurrency.sh`) can end up queued behind other pending
extrinsics long enough to exceed `agent-cli`'s own hardcoded 30s
`CompleteJoin` client deadline (`provider-agent/crates/agent-cli/src/
main.rs`) -- a wrapper `timeout` in these suites cannot extend that,
only retries can. `lib/common.sh`'s `agent_join_with_retry` retries up to
5 times with a short pause between attempts for exactly this reason; if
you add a new call site that joins a provider, route it through that
helper rather than calling `agent-cli join` directly.

If you are iterating on these suites locally and see repeated join
timeouts or `Priority is too low` errors, check for orphaned providers
first (`SELECT provider_id, registered_at FROM providers;` against the
Compose Postgres) -- a provider whose join extrinsic landed on-chain after
its test process already gave up and exited (the client-side timeout does
not mean the registration failed, only that the client stopped waiting for
it) leaks a row that never gets this suite matrix's own cleanup, and each
one is a permanent, unbounded retry loop per the gaps above. Delete stale
rows (cascading through `provider_chain_registrations`,
`provider_join_completions`, `provider_join_challenges`, then `providers`,
in that order) and restart `control-plane` to clear its in-memory offer-
withdrawal tracking before retrying.

## Writing a new suite

- Copy the shape of an existing suite, not a blank file: source
  `lib/common.sh` the same way, use `register_cleanup` for every resource,
  use `wait_until`/`wait_service_healthy` instead of a bare `sleep` loop.
- Never pass a shell *function* into `wait_until` (or anything else) through
  `bash -c "..."` -- a `bash -c` subshell does not inherit this shell's
  functions (`agent-cli`, `curl`, `grep`, and other external commands are
  fine; `heartbeat_ttl_positive`, `workload_state_is`, etc. are not).
  `wait_until` takes a real argv, so call the function directly:
  `wait_until 30 2 "description" my_function "$arg"`.
- Fixtures must contain synthetic credentials only (this directory's parent
  `tests/AGENTS.md` rule applies here too) and every unique resource name
  should derive from `unique_suffix`/`$E2E_RUN_ID` so two runs (or two
  suites) never collide.
- Query Postgres directly for assertions (`psql_exec`) rather than trusting
  a CLI's stdout formatting alone -- Postgres is the authoritative
  off-chain state (`AGENTS.md`), Redis and CLI output are not.
- Never write a fixture-building function whose only side effects
  (`register_cleanup`, `export`) are meant to reach the caller, then call
  it as `result="$(my_function ...)"`. Command substitution runs the
  function in a subshell; `register_cleanup` is safe to call this way
  (file-backed, see above), but a plain `export FOO=bar` made inside that
  subshell never reaches the parent shell. If a fixture builder needs to
  export something the *caller* will use afterward, either export it at
  the caller's own top level (as `lib/common.sh` now does for the mTLS
  client env, unconditionally, at file-scope) or have the function itself
  do everything that needs that export before returning, rather than
  relying on it leaking out.
