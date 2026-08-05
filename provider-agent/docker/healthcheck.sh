#!/bin/bash
set -euo pipefail

test -s "${OPENINFRA_AGENT_STATE_DIR:-/var/lib/openinfra-agent}/identity.key"
test -s "${OPENINFRA_AGENT_STATE_DIR:-/var/lib/openinfra-agent}/config.yaml"
exec 3<>/dev/tcp/127.0.0.1/50052
