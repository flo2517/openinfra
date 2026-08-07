#!/bin/sh
set -eu

if [ -z "${OPENINFRA_DEV_AUTHORITY_SEED:-}" ]; then
  echo "OPENINFRA_DEV_AUTHORITY_SEED is required for an authority" >&2
  exit 1
fi

base_path="${OPENINFRA_NODE_BASE_PATH:-/var/lib/openinfra}"
chain="${OPENINFRA_NODE_CHAIN:-openinfra-local}"

# This node's libp2p identity key. Unlike a vanilla substrate-node-
# template, this build does not auto-generate one on first run when a
# persistent --base-path is used (observed directly: NetworkKeyNotFound
# on a fresh volume) -- generate it once, idempotently, so a fresh
# volume (first boot, or after `make dev-clean`) starts cleanly instead
# of crash-looping on that error. A subsequent boot with the same
# volume leaves the existing key (and therefore this node's peer ID)
# untouched.
network_key_path="$base_path/chains/$chain/network/secret_ed25519"
if [ ! -f "$network_key_path" ]; then
  mkdir -p "$(dirname "$network_key_path")"
  openinfra-node key generate-node-key --file "$network_key_path"
fi

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
