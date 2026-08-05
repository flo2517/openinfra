#!/bin/sh
set -eu

if [ -z "${OPENINFRA_DEV_AUTHORITY_SEED:-}" ]; then
  echo "OPENINFRA_DEV_AUTHORITY_SEED is required for an authority" >&2
  exit 1
fi

base_path="${OPENINFRA_NODE_BASE_PATH:-/var/lib/openinfra}"
chain="${OPENINFRA_NODE_CHAIN:-openinfra-local}"

openinfra-node key insert \
  --base-path "$base_path" \
  --chain "$chain" \
  --scheme sr25519 \
  --suri "$OPENINFRA_DEV_AUTHORITY_SEED" \
  --key-type aura
openinfra-node key insert \
  --base-path "$base_path" \
  --chain "$chain" \
  --scheme ed25519 \
  --suri "$OPENINFRA_DEV_AUTHORITY_SEED" \
  --key-type gran

exec openinfra-node "$@"
