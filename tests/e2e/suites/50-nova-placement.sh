#!/usr/bin/env bash
# Suite 50: issue #24's Nova/Placement-compatible compute API (ADR-031 §4,
# PR #181) against the real Compose stack -- real Keystone token issuance,
# a real Glance-resolved server create/list/get/delete lifecycle actually
# reaching ACTIVE via the unmodified internal/orchestrator state machine
# (not mocked, not short-circuited), a Placement allocation read that
# reflects that same real scheduler/lease state, and a real quota-exceeded
# rejection. This is also the regression test for issue #24's remaining
# Glance-integration gap (internal/openstackapi/nova's server-create path
# resolving imageRef through internal/openstackapi/glance's registry
# instead of a caller-supplied digest passthrough): the imageRef this
# suite submits is an opaque Glance image_id, never a docker reference
# itself, and the workload that actually reaches RUNNING is the one whose
# real container backs the Glance-registered digest.
#
# Not run in CI today (like 00/10/20/40 -- see tests/e2e/AGENTS.md): needs
# the full Compose stack up via `make dev-up` first, same precondition
# every non-migrations suite already has.
#
# Deliberately out of scope, matching issue #24's own remaining
# boundaries (see internal/openstackapi/nova's package doc comment):
# console/migration/resize/hw-extra-specs (ADR-031 §4's permanent
# non-goals) and the wire-compatible `reboot` action (still unimplemented
# -- this system has no safe "redeploy a STOPPED workload" primitive, and
# a fake success path there is exactly what AGENTS.md's "no placeholder
# success paths" rule forbids). Neither is exercised here.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export E2E_REPO_ROOT="$repo_root"
# shellcheck source=tests/e2e/lib/common.sh
. "$repo_root/tests/e2e/lib/common.sh"

ensure_shared_binaries
require_stack_up postgres redis blockchain-node control-plane docker-socket-proxy provider-agent

openstack_http="${E2E_OPENSTACK_HTTP_ADDR:-127.0.0.1:8087}"
work_dir="$(mktemp -d)"
register_cleanup "rm -rf \"$work_dir\""

# issue_scoped_token <user_id> <raw_api_key> <project_id> -- real Keystone
# v3 POST /v3/auth/tokens, "password" method bridging an oiu_-prefixed API
# key onto a project-scoped token (internal/openstackapi/keystone's own
# documented wire-compatibility shape -- see issueToken's doc comment: the
# password field carries the raw API key, not a real password). Echoes
# the X-Subject-Token header value on success.
issue_scoped_token() {
  local user_id="$1" api_key="$2" project_id="$3"
  local headers_file body status
  headers_file="$(mktemp)"
  body="$(python3 -c '
import json, sys
user_id, api_key, project_id = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({"auth": {"identity": {"methods": ["password"], "password": {"user": {"id": user_id, "password": api_key}}}, "scope": {"project": {"id": project_id}}}}))
' "$user_id" "$api_key" "$project_id")"
  status="$(curl -sS -o /dev/null -D "$headers_file" -w '%{http_code}' \
    -X POST "http://${openstack_http}/v3/auth/tokens" \
    -H 'Content-Type: application/json' --data "$body")"
  if [[ "$status" != "201" ]]; then
    rm -f "$headers_file"
    fail "POST /v3/auth/tokens for project $project_id returned HTTP $status"
  fi
  local token
  token="$(grep -i '^X-Subject-Token:' "$headers_file" | awk '{print $2}' | tr -d '\r')"
  rm -f "$headers_file"
  [[ -n "$token" ]] || fail "POST /v3/auth/tokens returned 201 but no X-Subject-Token header"
  echo "$token"
}

# --- fixtures: a real user, project, and membership ----------------------
create_user_output="$("$E2E_BIN_DIR/controlplane-admin" create-user "e2e-nova-$(unique_suffix)")"
user_id="$(sed -n 's/^user_id: //p' <<<"$create_user_output")"
raw_api_key="$(sed -n 's/^api_key: //p' <<<"$create_user_output" | awk '{print $1}')"
[[ "$user_id" =~ ^[0-9a-f-]{36}$ ]] || fail "create-user did not return a user_id"
[[ "$raw_api_key" =~ ^oiu_[0-9a-f]{64}$ ]] || fail "create-user did not return an api_key"

create_project_output="$("$E2E_BIN_DIR/controlplane-admin" create-project "e2e-nova-$(unique_suffix)" "$user_id")"
project_id="$(sed -n 's/^project_id: //p' <<<"$create_project_output")"
[[ "$project_id" =~ ^[0-9a-f-]{36}$ ]] || fail "create-project did not return a project_id"
# One combined cleanup, registered once both ids are known, in strict FK
# dependency order within a single psql_exec transaction: api_keys first
# (matched by *either* user_id -- the unscoped key create-user minted --
# or project_id -- the project-scoped key issue_scoped_token mints below,
# which api_keys.project_id references, migration 000017), then
# project_quotas/project_memberships (both reference project_id), then
# projects, then users. Registering this as two separate cleanups (one
# per resource, in creation order) was tried first and found live to
# leave every project/quota row orphaned: the api_keys cleanup would only
# run *after* the project cleanup (reverse-registration-order execution),
# so DELETE FROM projects hit a live FK from the still-present
# project-scoped api_keys row, failed, and rolled back the whole
# multi-statement transaction -- the `|| true` on each psql_exec call
# swallows that failure silently rather than surfacing it as a cleanup
# error, so the leak was silent until checked directly against Postgres.
register_cleanup "psql_exec \"DELETE FROM api_keys WHERE user_id='$user_id' OR project_id='$project_id'; DELETE FROM project_quotas WHERE project_id='$project_id'; DELETE FROM project_memberships WHERE project_id='$project_id'; DELETE FROM projects WHERE project_id='$project_id'; DELETE FROM users WHERE user_id='$user_id';\" >/dev/null 2>&1 || true"

log "fixtures ready: user=$user_id project=$project_id"

# --- a real, disposable provider this suite fully owns --------------------
# Same reasoning as 00-happy-path.sh's own deploy section: a provider this
# suite joins, registers, and tears down itself, independent of whatever
# else is scheduled onto the always-on Compose provider-agent by other
# suites/tests in the same session.
deploy_agent_dir="$(mktemp -d)"
deploy_provider_id="$(start_provider_agent "$deploy_agent_dir" 50099)" \
  || fail "deploy agent failed to join/start"
log "disposable provider $deploy_provider_id joined and heartbeating"

# --- 1) real Keystone token issuance --------------------------------------
scoped_token="$(issue_scoped_token "$user_id" "$raw_api_key" "$project_id")"
log "Keystone issued a real project-scoped token for project $project_id"

# --- 2) Glance image registration -----------------------------------------
# A small, well-known image pinned by digest, exactly like
# 00-happy-path.sh's own deploy image choice (agent-executor runs every
# container with cap_drop=ALL + no-new-privileges; pause's whole job is to
# sit idle forever with zero privileges). Registered in Glance as
# source_ref (no digest) + digest_sha256, the real ADR-031/issue #26
# registry shape createServer must now resolve through (issue #24's
# Glance-integration fix) -- imageRef submitted below is the opaque
# glance_image_id, never this reference itself.
deploy_image="registry.k8s.io/pause:3.9"
docker pull -q "$deploy_image" >/dev/null
deploy_image_ref="$(docker inspect --format='{{index .RepoDigests 0}}' "$deploy_image")"
image_source_ref="${deploy_image_ref%@*}"
image_digest="${deploy_image_ref##*@sha256:}"
[[ "$image_digest" =~ ^[a-f0-9]{64}$ ]] || fail "could not parse a sha256 digest out of $deploy_image_ref"

image_body="$(python3 -c '
import json, sys
name, source_ref, digest = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({"name": name, "direct_url": source_ref, "os_hash_value": digest, "visibility": "private"}))
' "e2e-nova-image-$(unique_suffix)" "$image_source_ref" "$image_digest")"
image_response="$(curl -sS -w '\n%{http_code}' -X POST "http://${openstack_http}/v2/images" \
  -H "X-Auth-Token: $scoped_token" -H 'Content-Type: application/json' --data "$image_body")"
image_status="$(tail -n1 <<<"$image_response")"
image_json="$(sed '$d' <<<"$image_response")"
[[ "$image_status" == "201" ]] || fail "POST /v2/images returned HTTP $image_status: $image_json"
glance_image_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$image_json")"
[[ "$glance_image_id" =~ ^[0-9a-f-]{36}$ ]] || fail "image registration did not return an id"
register_cleanup "psql_exec \"DELETE FROM glance_images WHERE image_id='$glance_image_id';\" >/dev/null 2>&1 || true"
log "registered Glance image $glance_image_id -> $deploy_image_ref"

# --- 3) server create -> real orchestrator -> ACTIVE, list, get -----------
create_body="$(python3 -c '
import json, sys
name, image_id = sys.argv[1], sys.argv[2]
print(json.dumps({"server": {"name": name, "imageRef": image_id, "flavorRef": "1", "metadata": {"suite": "50-nova-placement"}}}))
' "e2e-nova-server-$(unique_suffix)" "$glance_image_id")"
create_response="$(curl -sS -w '\n%{http_code}' -X POST "http://${openstack_http}/v2.1/${project_id}/servers" \
  -H "X-Auth-Token: $scoped_token" -H 'Content-Type: application/json' --data "$create_body")"
create_status="$(tail -n1 <<<"$create_response")"
create_json="$(sed '$d' <<<"$create_response")"
[[ "$create_status" == "202" ]] || fail "POST /servers returned HTTP $create_status: $create_json"
server_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["server"]["id"])' <<<"$create_json")"
[[ "$server_id" =~ ^[0-9a-f-]{36}$ ]] || fail "server create did not return a UUID id"
register_cleanup "psql_exec \"DELETE FROM nova_server_metadata WHERE workload_id='$server_id'; DELETE FROM workloads WHERE workload_id='$server_id';\" >/dev/null 2>&1 || true"
log "created Nova server $server_id (imageRef=$glance_image_id, resolved via Glance)"

list_response="$(curl -sS "http://${openstack_http}/v2.1/${project_id}/servers" -H "X-Auth-Token: $scoped_token")"
list_has_server="$(python3 -c 'import json,sys; ids=[s["id"] for s in json.load(sys.stdin)["servers"]]; print("yes" if sys.argv[1] in ids else "no")' "$server_id" <<<"$list_response")"
[[ "$list_has_server" == "yes" ]] || fail "GET /servers did not include $server_id: $list_response"
log "server list includes $server_id"

server_status=""
for _ in $(seq 1 60); do
  get_response="$(curl -sS "http://${openstack_http}/v2.1/${project_id}/servers/${server_id}" -H "X-Auth-Token: $scoped_token")"
  server_status="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["server"]["status"])' <<<"$get_response")"
  [[ "$server_status" == "ACTIVE" || "$server_status" == "ERROR" ]] && break
  sleep 3
done
[[ "$server_status" == "ACTIVE" ]] || fail "server $server_id never reached ACTIVE (last status: $server_status; $get_response)"
log "server $server_id reached ACTIVE via the real, unmodified orchestrator state machine"

# Postgres is authoritative (AGENTS.md) -- confirm a real container backs
# the ACTIVE status the HTTP layer just reported, and register its
# cleanup the instant it's known (even if a later assertion fails).
container_id="$(psql_exec "SELECT container_id FROM workloads WHERE workload_id='$server_id';" | tr -d '[:space:]')"
[[ -n "$container_id" ]] || fail "RUNNING workload $server_id has no container_id in Postgres"
register_cleanup "docker rm -f \"$container_id\" >/dev/null 2>&1 || true"
[[ "$(docker inspect --format='{{.State.Running}}' "$container_id")" == "true" ]] \
  || fail "server $server_id reported ACTIVE but container $container_id is not actually running"
log "server $server_id backed by real running container $container_id"

# --- 4) Placement allocation reflects real scheduler state ----------------
# Whichever schedulable provider the real ranker actually picked -- not
# necessarily the disposable one this suite joined above, since the
# always-on Compose provider-agent is an equally eligible ACTIVE
# candidate and the ranker is free to prefer it. Either is a "real
# scheduler decision"; this suite only needs to read back whichever one
# it was, not dictate it.
provider_id="$(psql_exec "SELECT provider_id FROM workloads WHERE workload_id='$server_id';" | tr -d '[:space:]')"
[[ -n "$provider_id" ]] || fail "RUNNING workload $server_id has no provider_id"
log "server $server_id was scheduled onto provider $provider_id"

alloc_response="$(curl -sS "http://${openstack_http}/allocations/${server_id}" -H "X-Auth-Token: $scoped_token")"
alloc_vcpu="$(python3 -c '
import json, sys
body = json.load(sys.stdin)
alloc = body.get("allocations", {}).get(sys.argv[1])
print(alloc["resources"]["VCPU"] if alloc else "")
' "$provider_id" <<<"$alloc_response")"
[[ "$alloc_vcpu" == "1" ]] || fail "GET /allocations/$server_id under provider $provider_id: VCPU=$alloc_vcpu, want 1 (oi.small); body=$alloc_response"
log "Placement allocation for consumer $server_id reflects real scheduler state: 1 VCPU on provider $provider_id"

usages_response="$(curl -sS "http://${openstack_http}/resource_providers/${provider_id}/usages" -H "X-Auth-Token: $scoped_token")"
usages_vcpu="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["usages"]["VCPU"])' <<<"$usages_response")"
[[ "$usages_vcpu" -ge 1 ]] || fail "GET /resource_providers/$provider_id/usages: VCPU=$usages_vcpu, want >=1 while $server_id is RUNNING; body=$usages_response"
log "Placement resource-provider usages for $provider_id reflect the committed reservation (VCPU=$usages_vcpu)"

# --- 5) delete -> real STOPPING/STOPPED path, container removed ----------
delete_status="$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE \
  "http://${openstack_http}/v2.1/${project_id}/servers/${server_id}" -H "X-Auth-Token: $scoped_token")"
[[ "$delete_status" == "204" ]] || fail "DELETE /servers/$server_id returned HTTP $delete_status"

final_status=""
for _ in $(seq 1 30); do
  get_response="$(curl -sS "http://${openstack_http}/v2.1/${project_id}/servers/${server_id}" -H "X-Auth-Token: $scoped_token")"
  final_status="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["server"]["status"])' <<<"$get_response")"
  [[ "$final_status" == "SHUTOFF" ]] && break
  sleep 3
done
[[ "$final_status" == "SHUTOFF" ]] || fail "server $server_id never reached SHUTOFF after delete (last: $final_status)"
# novaStatus maps both STOPPING and STOPPED to SHUTOFF (response.go), so
# the HTTP layer can report SHUTOFF a moment before the authoritative
# Postgres row actually finishes its STOPPING -> STOPPED transition (the
# lease-completion on-chain wait in internal/orchestrator/worker.go's
# STOPPING case) -- poll the real state directly rather than assuming the
# two are simultaneous.
wait_until 30 2 "authoritative Postgres state for $server_id is STOPPED" workload_state_is "$server_id" "STOPPED" \
  || fail "authoritative Postgres state for $server_id is not STOPPED after delete (got $(workload_state "$server_id"))"
# See 00-happy-path.sh's identical wait for why this is generous: pause has
# no SIGTERM handler, so bollard's stop grace period routinely runs its
# full course before Docker SIGKILLs it.
wait_until 90 1 "container $container_id removed after delete" \
  bash -c "! docker inspect \"$container_id\" >/dev/null 2>&1" \
  || fail "container $container_id still present after server delete reported SHUTOFF"
log "server $server_id deleted: SHUTOFF via HTTP, STOPPED in Postgres, container $container_id removed"

# --- 6) quota-exceeded rejection (a second, tightly-quota'd project) -----
quota_user_output="$("$E2E_BIN_DIR/controlplane-admin" create-user "e2e-nova-quota-$(unique_suffix)")"
quota_user_id="$(sed -n 's/^user_id: //p' <<<"$quota_user_output")"
quota_api_key="$(sed -n 's/^api_key: //p' <<<"$quota_user_output" | awk '{print $1}')"

quota_project_output="$("$E2E_BIN_DIR/controlplane-admin" create-project "e2e-nova-quota-$(unique_suffix)" "$quota_user_id")"
quota_project_id="$(sed -n 's/^project_id: //p' <<<"$quota_project_output")"
# Combined, FK-ordered cleanup -- see the identical comment on the primary
# user/project fixture above for why this must be one statement, not two.
register_cleanup "psql_exec \"DELETE FROM api_keys WHERE user_id='$quota_user_id' OR project_id='$quota_project_id'; DELETE FROM project_quotas WHERE project_id='$quota_project_id'; DELETE FROM project_memberships WHERE project_id='$quota_project_id'; DELETE FROM projects WHERE project_id='$quota_project_id'; DELETE FROM users WHERE user_id='$quota_user_id';\" >/dev/null 2>&1 || true"

# oi.small (flavor "1") needs 1000 CPU millicores (CPUCoresToMillicores(1));
# 500 is deliberately too small for even the smallest flavor, the same
# choice internal/openstackapi/nova's own
# TestCreateServerRejectsWhenProjectQuotaIsExceeded makes at the Go-test
# layer.
"$E2E_BIN_DIR/controlplane-admin" set-quota "$quota_project_id" 500 100000 100000 100 >/dev/null

quota_scoped_token="$(issue_scoped_token "$quota_user_id" "$quota_api_key" "$quota_project_id")"

# imageRef is never resolved for this request -- createServer's own
# ordering (name -> imageRef non-empty -> flavor -> quota -> Glance
# resolution) means a quota rejection happens before Glance is ever
# consulted, so any non-empty placeholder is fine here.
quota_create_body="$(python3 -c '
import json, sys
print(json.dumps({"server": {"name": sys.argv[1], "imageRef": "unused-quota-check", "flavorRef": "1"}}))
' "e2e-nova-quota-server-$(unique_suffix)")"
quota_response="$(curl -sS -w '\n%{http_code}' -X POST "http://${openstack_http}/v2.1/${quota_project_id}/servers" \
  -H "X-Auth-Token: $quota_scoped_token" -H 'Content-Type: application/json' --data "$quota_create_body")"
quota_status="$(tail -n1 <<<"$quota_response")"
quota_json="$(sed '$d' <<<"$quota_response")"
[[ "$quota_status" == "403" ]] || fail "quota-exceeded create returned HTTP $quota_status, want 403: $quota_json"
quota_has_fault="$(python3 -c 'import json,sys; body=json.load(sys.stdin); print("yes" if "forbidden" in body else "no")' <<<"$quota_json")"
[[ "$quota_has_fault" == "yes" ]] || fail "403 body missing the \"forbidden\" fault wrapper: $quota_json"
log "quota-exceeded create correctly rejected with 403: $quota_json"

quota_list_response="$(curl -sS "http://${openstack_http}/v2.1/${quota_project_id}/servers" -H "X-Auth-Token: $quota_scoped_token")"
quota_list_count="$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)["servers"]))' <<<"$quota_list_response")"
[[ "$quota_list_count" == "0" ]] || fail "quota-rejected create was not actually a no-op: $quota_list_count server(s) listed for project $quota_project_id"
log "quota-exceeded create was a true no-op: no server was created"

echo "E2E nova-placement suite PASSED"
