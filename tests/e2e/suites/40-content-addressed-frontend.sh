#!/usr/bin/env bash
# Suite 40: ADR-037 (content-addressed dashboard frontend distribution,
# issue #35) end to end against the real Compose stack -- the self-hosted
# kubo node actually pinning and serving a release's bytes, the signed
# manifest actually being verifiable, GET /.well-known/openinfra-frontend
# actually serving it, and the dashboard's CORS/origin-allowlist actually
# rejecting a disallowed Origin and honoring one the just-published
# release trusts -- proving ADR-037 §11(a)/(b)/(d) are live, not
# aspirational.
#
# Not run in CI today (like 00/10/20 -- see tests/e2e/AGENTS.md): needs
# the full Compose stack (postgres, control-plane, ipfs) up via `make
# dev-up` first, same precondition every non-migrations suite already
# has. §11(c) (read-only rendering from a third-party public mirror
# gateway, e.g. dweb.link) and §11(e) (a real browser's CSP <meta>
# enforcement) are deliberately out of this suite's scope -- (c) needs
# real internet egress to a gateway this project does not operate, and
# (e) needs a real browser engine, neither of which this shell-based
# harness can exercise; both are named here as the concrete remaining gap
# against ADR-037 §11's full list, not silently skipped.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export E2E_REPO_ROOT="$repo_root"
# shellcheck source=tests/e2e/lib/common.sh
. "$repo_root/tests/e2e/lib/common.sh"

require_stack_up postgres control-plane ipfs

control_plane_http="${CONTROL_PLANE_HTTP_ADDR:-127.0.0.1:8080}"
work_dir="$(mktemp -d)"
register_cleanup "rm -rf \"$work_dir\""

# --- 1) a real, minimal release tree, pinned via the real kubo node -----
# Deliberately not control-plane/internal/dashboard/assets itself (this
# suite must not depend on that directory's exact current contents, only
# on the mechanism): a fixed two-file tree this suite fully controls.
release_tree="$work_dir/release"
mkdir -p "$release_tree"
printf '<html>e2e-40 release</html>' >"$release_tree/index.html"
printf '{"api_origin":"","allowed_login_origins":["https://e2e-40-allowed.example.org"]}' >"$release_tree/config.json"

# ipfs add needs the tree *inside* the ipfs container -- docker cp it in,
# run the exact reproducibility-load-bearing flags ADR-037 §2 step 2
# fixes, read the CID back out.
container_tree="/tmp/e2e-40-release-$run_id"
docker compose --env-file "$repo_root/.env" -f "$repo_root/deployments/docker-compose.yml" \
  cp "$release_tree" "ipfs:$container_tree"
cid="$(docker compose --env-file "$repo_root/.env" -f "$repo_root/deployments/docker-compose.yml" \
  exec -T ipfs ipfs add -Q -r --cid-version=1 --raw-leaves "$container_tree" | tr -d '\r')"
[[ "$cid" =~ ^bafy ]] || fail "ipfs add did not return a CIDv1 (got: $cid)"
log "pinned release tree as $cid"

# The self-hosted gateway must actually serve it, byte for byte -- ADR-037
# §1's "content-addressing is native" claim, checked against the real
# node, not asserted.
gateway_port="${IPFS_GATEWAY_PORT:-8081}"
served="$(curl -fsS "http://127.0.0.1:${gateway_port}/ipfs/${cid}/index.html")"
[[ "$served" == "<html>e2e-40 release</html>" ]] || fail "kubo gateway did not serve the pinned tree's exact bytes"
log "self-hosted gateway served the pinned CID's exact bytes"

# --- 2) build, sign, and publish a real manifest for that CID -----------
key_path="$work_dir/release-key"
(cd "$repo_root/control-plane" && go run ./cmd/frontendrelease keygen -out "$key_path") \
  || fail "keygen failed"

# `manifest` (not `build`): this suite already has a real CID from the
# ipfs container above, computed inside it (§1) -- `build`'s own CID
# computation step shells out to a *local* `ipfs` binary, which cannot
# reach the Compose ipfs container's daemon from here. `manifest` hashes
# -dir exactly as `build` does and takes the already-known CID directly.
unsigned_manifest="$work_dir/unsigned.json"
(cd "$repo_root/control-plane" && go run ./cmd/frontendrelease manifest \
  -dir "$release_tree" -cid "$cid" \
  -allowed-origins 'https://e2e-40-allowed.example.org' \
  -out "$unsigned_manifest") \
  || fail "manifest failed"

signed_manifest="$work_dir/signed.json"
(cd "$repo_root/control-plane" && go run ./cmd/frontendrelease sign -key "$key_path" -manifest "$unsigned_manifest" -out "$signed_manifest") \
  || fail "sign failed"
(cd "$repo_root/control-plane" && go run ./cmd/frontendrelease verify -pubkey "$key_path.pub.hex" -manifest "$signed_manifest") \
  || fail "the signed manifest does not verify against its own freshly generated key"
log "built and signed a real manifest for $cid"

database_url="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT:-5432}/${POSTGRES_DB}?sslmode=disable"
release_id="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['release_id'])" "$signed_manifest")"
register_cleanup "psql_exec \"DELETE FROM frontend_releases WHERE release_id='$release_id';\" >/dev/null 2>&1 || true"
DATABASE_URL="$database_url" bash -c \
  "cd '$repo_root/control-plane' && go run ./cmd/frontendrelease publish -pubkey '$key_path.pub.hex' -manifest '$signed_manifest'" \
  || fail "publish failed"
log "published release $release_id"

# --- 3) GET /.well-known/openinfra-frontend serves it, verbatim ---------
wellknown_body="$(curl -fsS "http://${control_plane_http}/.well-known/openinfra-frontend")"
served_cid="$(python3 -c "import json,sys; print(json.load(sys.stdin)['cid'])" <<<"$wellknown_body")"
[[ "$served_cid" == "$cid" ]] || fail ".well-known served cid=$served_cid, want the just-published $cid"
log ".well-known/openinfra-frontend serves the just-published release's signed manifest"

# --- 4) CORS: the just-published release's allowed_login_origins is live,
# and a disallowed origin is rejected -- ADR-037 §4/§7's actual
# phishing-resistance control, exercised against the live server, not a
# unit test double.
allowed_status="$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'Origin: https://e2e-40-allowed.example.org' "http://${control_plane_http}/api/v1/me")"
[[ "$allowed_status" == "401" ]] || fail "an allowlisted origin's credentialed request = HTTP $allowed_status, want 401 (unauthenticated, but past the CORS gate -- 403 would mean CORS itself blocked it)"
log "the just-published release's allowed_login_origins is live: allowed origin reached the real handler"

disallowed_status="$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'Origin: https://evil-gateway.example' "http://${control_plane_http}/api/v1/me")"
[[ "$disallowed_status" == "403" ]] || fail "a disallowed origin's credentialed request = HTTP $disallowed_status, want 403"
log "a disallowed origin was rejected by the CORS allowlist before reaching the handler"

log "ADR-037 §11(a)/(b)/(d) passed: pinning+gateway, signed-manifest trust root, and live CORS enforcement all verified against the real stack"
