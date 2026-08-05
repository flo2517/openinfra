#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
compose_file="$repo_root/deployments/docker-compose.yml"
env_file="$repo_root/.env"

test -f "$env_file"
docker compose --env-file "$env_file" -f "$compose_file" config --quiet

rendered=$(docker compose --env-file "$env_file" -f "$compose_file" config)
grep -q 'target: /var/lib/openinfra-agent' <<<"$rendered"
grep -q 'DOCKER_HOST: tcp://docker-socket-proxy:2375' <<<"$rendered"
grep -q 'name: openinfra_docker-executor' <<<"$rendered"
grep -q 'internal: true' <<<"$rendered"
if sed -n '/provider-agent:/,/^[^ ]/p' "$compose_file" | grep -q '/var/run/docker.sock'; then
  echo 'Provider Agent must not mount the Docker socket directly' >&2
  exit 1
fi
