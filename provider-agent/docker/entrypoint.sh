#!/bin/bash
set -euo pipefail

umask 077
state_dir=${OPENINFRA_AGENT_STATE_DIR:-/var/lib/openinfra-agent}
config_file="$state_dir/config.yaml"
identity_file="$state_dir/identity.key"
mkdir -p "$state_dir/.openinfra-state"

if [[ ! -s "$identity_file" ]]; then
  temporary_key="$identity_file.tmp"
  head -c 32 /dev/urandom > "$temporary_key"
  chmod 600 "$temporary_key"
  mv "$temporary_key" "$identity_file"
fi

if [[ ! -s "$config_file" ]]; then
  temporary_config="$config_file.tmp"
  cat > "$temporary_config" <<EOF
agent:
  id: null
  protocol_version: "1"
  agent_version: "0.1.0"
  listen_address: "0.0.0.0:50052"
  advertised_endpoint: "${OPENINFRA_AGENT_ADVERTISED_ENDPOINT:-https://provider-agent:50052}"
security:
  key_path: "$identity_file"
control_plane:
  endpoint: "${OPENINFRA_CONTROL_PLANE_ENDPOINT:-https://control-plane:50051}"
executor:
  state_path: "$state_dir/.openinfra-state"
  max_workloads: ${OPENINFRA_AGENT_MAX_WORKLOADS:-8}
  max_cpu_cores: ${OPENINFRA_AGENT_MAX_CPU_CORES:-8.0}
  max_memory_mb: ${OPENINFRA_AGENT_MAX_MEMORY_MB:-16384}
  pids_limit: ${OPENINFRA_AGENT_PIDS_LIMIT:-128}
  max_egress_mbps: ${OPENINFRA_AGENT_MAX_EGRESS_MBPS:-10000}
EOF
  chmod 600 "$temporary_config"
  mv "$temporary_config" "$config_file"
fi

cd "$state_dir"
if grep -Eq '^  id: (null|~)$' "$config_file"; then
  /usr/local/bin/openinfra-agent join
fi

exec /usr/local/bin/openinfra-agent start
