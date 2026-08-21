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

# go_status runs `networkvalidator status` for key_file and prints its
# combined stdout+stderr, preserving its exit status -- split out of
# is_registered so a caller that needs the actual diagnostic text (e.g.
# bootstrap_one's final-failure report below) doesn't have to re-derive
# it, and so is_registered itself stays a plain predicate.
go_status() {
  local key_file=$1
  SUBSTRATE_RPC_URL="$SUBSTRATE_RPC_URL" VALIDATOR_SIGNER_KEY_FILE="$key_file" \
    "$GO" run ./cmd/networkvalidator status 2>&1
}

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
  output=$(go_status "$key_file") || return 1
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
    # Retried and failure-tolerant for the same reason the register loop
    # below is (PR #135 review): a bare, unretried call here would let a
    # single transient chain-RPC hiccup on the funding transfer abort
    # this whole script under `set -e`, even though the very next step
    # (register_validator) is explicitly designed to tolerate exactly
    # that class of failure. fund_output is kept so the *last* attempt's
    # output can be surfaced if funding never succeeds -- distinguishing
    # a permanent misconfiguration (bad SUBSTRATE_SIGNER_KEY_FILE, wrong
    # SUBSTRATE_RPC_URL) from a transient one, instead of both looking
    # identical the way a fully discarded/never-retried failure would.
    local fund_output="" attempt funded=0
    for attempt in $(seq 1 10); do
      if fund_output=$(SUBSTRATE_RPC_URL="$SUBSTRATE_RPC_URL" SUBSTRATE_SIGNER_KEY_FILE="$bridge_key" \
          "$GO" run ./cmd/controlplane-admin fund-account "$account" "$FUND_AMOUNT" 2>&1); then
        funded=1
        break
      fi
      sleep 3
    done
    if [[ "$funded" -ne 1 ]]; then
      echo "bootstrap-network-validators: $service funding failed after $attempt attempts; last \`fund-account\` output:" >&2
      echo "$fund_output" >&2
      exit 1
    fi

    # Wait for the funding transfer to actually finalize before the
    # *first* register_validator attempt, rather than racing it in
    # immediately. Confirmed live: register_validator on a still-zero
    # balance is rejected at the transaction-pool validity stage (RPC
    # error 1010, "Inability to pay some fees"), not just at dispatch --
    # and because this account's every register_validator submission is
    # byte-identical (same nonce=0, same call, an immortal era), the pool
    # then *bans* that exact extrinsic hash (RPC error 1012, "Transaction
    # is temporarily banned") for a long, fixed cooldown. Once that
    # happens, every retry in the loop below keeps resubmitting the same
    # banned bytes and cannot succeed until the ban itself expires -- no
    # amount of retrying works around it, so avoiding a premature first
    # attempt matters far more here than for most retry loops. 15s
    # comfortably clears this chain's observed finality lag (block time
    # ~3s; finalized trails best by a couple of blocks in practice).
    sleep 15

    echo "bootstrap-network-validators: registering $service (stake=$VALIDATOR_STAKE)"
    local register_output="" registered=0
    for attempt in $(seq 1 20); do
      # register_validator can legitimately fail transiently here (most
      # often: the funding transfer above hasn't finalized yet, so free
      # balance doesn't yet cover the stake reservation) -- `|| true`
      # keeps this retry loop alive on that failure instead of `set -e`
      # aborting the whole bootstrap on the first attempt; is_registered
      # below is what actually decides whether to keep retrying.
      # register_output is kept (not discarded to /dev/null) so the last
      # attempt's text can be surfaced below if registration never
      # succeeds.
      register_output=$(SUBSTRATE_RPC_URL="$SUBSTRATE_RPC_URL" VALIDATOR_SIGNER_KEY_FILE="$key_file" \
        "$GO" run ./cmd/networkvalidator register "$VALIDATOR_STAKE" 2>&1) || true
      sleep 3
      if is_registered "$key_file"; then
        registered=1
        break
      fi
    done
    if [[ "$registered" -ne 1 ]]; then
      echo "bootstrap-network-validators: $service did not become registered after $attempt attempts" >&2
      echo "bootstrap-network-validators: last \`register $VALIDATOR_STAKE\` output:" >&2
      echo "$register_output" >&2
      echo "bootstrap-network-validators: last \`status\` output:" >&2
      go_status "$key_file" >&2 || true
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
