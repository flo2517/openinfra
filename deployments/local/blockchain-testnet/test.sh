#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
compose_file="$repo_root/deployments/local/blockchain-testnet/docker-compose.yml"

rpc() {
  local port="$1"
  local method="$2"
  curl --fail --silent --show-error \
    --header 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[]}" \
    "http://127.0.0.1:$port/"
}

for _ in $(seq 1 30); do
  connected=true
  for port in 9954 9955 9956; do
    health="$(rpc "$port" system_health)"
    if ! python3 - "$port" "$health" <<'PY'
import json, sys
port, payload = sys.argv[1:]
result = json.loads(payload).get("result", {})
if result.get("peers", 0) < 2 or result.get("isSyncing"):
    raise SystemExit(1)
PY
    then
      connected=false
      break
    fi
  done
  if [[ "$connected" == true ]]; then
    break
  fi
  sleep 1
done
if [[ "$connected" != true ]]; then
  echo "the three-node peer topology did not converge" >&2
  exit 1
fi

initial="$(rpc 9956 chain_getFinalizedHead)"
initial_hash="$(python3 - "$initial" <<'PY'
import json, sys
print(json.loads(sys.argv[1])["result"])
PY
)"

for _ in $(seq 1 12); do
  sleep 1
  current="$(rpc 9956 chain_getFinalizedHead)"
  current_hash="$(python3 - "$current" <<'PY'
import json, sys
print(json.loads(sys.argv[1])["result"])
PY
)"
  if [[ "$current_hash" != "$initial_hash" ]]; then
    break
  fi
done

if [[ "$current_hash" == "$initial_hash" ]]; then
  echo "finalized head did not advance" >&2
  exit 1
fi

for port in 9954 9955; do
  node_hash="$(rpc "$port" chain_getFinalizedHead | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')"
  if [[ "$node_hash" != "$current_hash" ]]; then
    echo "RPC $port finalized $node_hash, expected $current_hash" >&2
    exit 1
  fi
done

header="$(curl --fail --silent --show-error \
  --header 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"chain_getHeader\",\"params\":[\"$current_hash\"]}" \
  http://127.0.0.1:9956/)"
number="$(python3 - "$header" <<'PY'
import json, sys
print(int(json.loads(sys.argv[1])["result"]["number"], 16))
PY
)"
if (( number < 1 )); then
  echo "expected a finalized block above genesis" >&2
  exit 1
fi

echo "Aura/GRANDPA testnet healthy: 3 nodes, finalized block #$number ($current_hash)"
