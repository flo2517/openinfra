#!/usr/bin/env bash
set -euo pipefail

# Funds and registers each Network Validator signing key that
# generate-dev-certs.sh generated (ADR-011/013) against whichever
# networkvalidator* Compose services are actually running -- the default
# stack's single `networkvalidator`, plus `networkvalidator-2`/
# `networkvalidator-3` when the opt-in "multi-node" Compose profile is
# enabled (COMPOSE_PROFILES=multi-node). Run by `make dev-up` after
# `docker compose ... up -d --wait`, i.e. only once the chain and
# Control Plane are already healthy -- unlike cert/key generation, this
# step needs a live chain to submit extrinsics against, so it cannot run
# alongside generate-dev-certs.sh.
#
# Every extrinsic here runs on the host, over the Compose stack's
# host-exposed ports (127.0.0.1:9944), the same convention this repo's
# other dev bootstrap steps already use (see README.md's Provider Join
# development flow running agent-cli directly on the host). Idempotent:
# safe to re-run on every `make dev-up`, including against an
# already-bootstrapped stack -- see is_registered below.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

GO=${GO:-go}
SUBSTRATE_RPC_URL=${SUBSTRATE_RPC_URL:-http://127.0.0.1:9944}
# Twice pallet-network-validator's MinStake (blockchain/runtime/src/
# lib.rs: MinValidatorStake=1_000), plus a small buffer above the exact
# reserved amount so ExistentialDeposit headroom is never in question --
# this runtime has no pallet-transaction-payment (AGENTS.md's no-floats,
# narrow-integer-balances design; confirmed directly: not present in
# blockchain/runtime/src/lib.rs), so there are no transaction fees to
# additionally cover here.
VALIDATOR_STAKE=${VALIDATOR_STAKE:-2000}
FUND_AMOUNT=$((VALIDATOR_STAKE + 50))

bridge_key="$repo_root/deployments/local/certs/bridge-key.pem"
validator_dir="$repo_root/deployments/local/validators"
compose_args=(--env-file "$repo_root/.env" -f "$repo_root/deployments/docker-compose.yml")

if [[ ! -f "$bridge_key" ]]; then
  echo "bootstrap-network-validators: $bridge_key does not exist -- run generate-dev-certs.sh (or make dev-up) first" >&2
  exit 1
fi

echo "bootstrap-network-validators: waiting for $SUBSTRATE_RPC_URL to answer system_health..."
chain_ready=0
for _ in $(seq 1 60); do
  if curl --fail --silent --show-error -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]}' \
      "$SUBSTRATE_RPC_URL/" 2>/dev/null | grep -q '"result"'; then
    chain_ready=1
    break
  fi
  sleep 2
done
if [[ "$chain_ready" -ne 1 ]]; then
  echo "bootstrap-network-validators: $SUBSTRATE_RPC_URL never became healthy" >&2
  exit 1
fi

# Only the services Compose actually started -- so this script adapts to
# whichever profile `make dev-up` was run with, instead of hard-coding a
# validator count that would drift from docker-compose.yml.
running_services=$(docker compose "${compose_args[@]}" ps --status running --services)

# is_registered treats any failure to even run `status` (a transient RPC
# hiccup, not just "not registered yet") as "not registered": the safe
# direction to be wrong in is under-reporting registration and re-
# attempting funding/registration (harmless -- a repeat transfer costs
# the bridge account a negligible amount of its 1,000,000-unit genesis
# balance, and a repeat register_validator fails harmlessly as
# AlreadyRegistered, see pallet-network-validator's register_validator),
# never over-reporting it and silently skipping a validator that in fact
# still needs bootstrapping.
is_registered() {
  local key_file=$1 output
  output=$(SUBSTRATE_RPC_URL="$SUBSTRATE_RPC_URL" VALIDATOR_SIGNER_KEY_FILE="$key_file" \
    "$GO" run ./cmd/networkvalidator status 2>&1) || return 1
  ! grep -q "not registered" <<<"$output"
}

bootstrap_one() {
  local service=$1 key_name=$2
  local key_file="$validator_dir/$key_name-key.pem"
  local public_file="$validator_dir/$key_name-public.hex"

  if [[ ! -f "$key_file" || ! -f "$public_file" ]]; then
    echo "bootstrap-network-validators: $key_file/$public_file missing -- run generate-dev-certs.sh (or make dev-up) first" >&2
    exit 1
  fi

  (
    cd "$repo_root/control-plane"
    if is_registered "$key_file"; then
      echo "bootstrap-network-validators: $service already registered, skipping"
      return
    fi

    local account
    account=$(tr -d '[:space:]' < "$public_file")
    echo "bootstrap-network-validators: funding $service (account=$account, amount=$FUND_AMOUNT)"
    SUBSTRATE_RPC_URL="$SUBSTRATE_RPC_URL" SUBSTRATE_SIGNER_KEY_FILE="$bridge_key" \
      "$GO" run ./cmd/controlplane-admin fund-account "$account" "$FUND_AMOUNT"

    echo "bootstrap-network-validators: registering $service (stake=$VALIDATOR_STAKE)"
    local attempt registered=0
    for attempt in $(seq 1 20); do
      # register_validator can legitimately fail transiently here (most
      # often: the funding transfer above hasn't finalized yet, so free
      # balance doesn't yet cover the stake reservation) -- `|| true`
      # keeps this retry loop alive on that failure instead of `set -e`
      # aborting the whole bootstrap on the first attempt; is_registered
      # below is what actually decides whether to keep retrying.
      SUBSTRATE_RPC_URL="$SUBSTRATE_RPC_URL" VALIDATOR_SIGNER_KEY_FILE="$key_file" \
        "$GO" run ./cmd/networkvalidator register "$VALIDATOR_STAKE" >/dev/null 2>&1 || true
      sleep 3
      if is_registered "$key_file"; then
        registered=1
        break
      fi
    done
    if [[ "$registered" -ne 1 ]]; then
      echo "bootstrap-network-validators: $service did not become registered after $attempt attempts" >&2
      exit 1
    fi
    echo "bootstrap-network-validators: $service registered"
  )
}

for entry in "networkvalidator:validator" "networkvalidator-2:validator-2" "networkvalidator-3:validator-3"; do
  service=${entry%%:*}
  key_name=${entry#*:}
  if echo "$running_services" | grep -qx "$service"; then
    bootstrap_one "$service" "$key_name"
  else
    echo "bootstrap-network-validators: $service is not running, skipping"
  fi
done

echo "bootstrap-network-validators: done"
