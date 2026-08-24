#!/usr/bin/env bash
# tests/e2e/run.sh -- dispatcher for the E2E suite matrix (issue #17).
#
# Usage:
#   tests/e2e/run.sh                # run every suite in tests/e2e/suites/, in order
#   tests/e2e/run.sh 00-happy-path  # run just one suite (name, with or without .sh)
#   tests/e2e/run.sh 00-happy-path 20-chaos-injection   # run a chosen subset, in the order given
#
# Each suite is a fully independent, self-cleaning script (own fixtures,
# own cleanup trap, own timeout -- see tests/e2e/lib/common.sh and
# tests/e2e/AGENTS.md); this script's only job is to build the shared
# binaries once, run the chosen suites in sequence under a wall-clock
# timeout each, and stop at the first failure so a broken suite doesn't
# run the next one against whatever state it left behind.
#
# Requires the Compose dev stack already running (`make dev-up`) and a
# populated `.env` (`cp .env.example .env`), same as the pre-restructure
# tests/e2e/run.sh always did.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
suites_dir="$repo_root/tests/e2e/suites"

test -f "$repo_root/.env" || {
  echo "run.sh: $repo_root/.env is missing -- run 'cp .env.example .env' first" >&2
  exit 1
}

export E2E_REPO_ROOT="$repo_root"
# shellcheck source=tests/e2e/lib/common.sh
. "$repo_root/tests/e2e/lib/common.sh"
# common.sh already built $E2E_BIN_DIR and registered its own cleanup;
# E2E_BIN_DIR/E2E_RUN_ID are exported so every suite subprocess below
# reuses the same binaries and run-unique resource-naming suffix instead
# of rebuilding/re-deriving its own.

# Per-suite wall-clock budget. Generous on purpose (real on-chain finality
# waits, real container restarts) -- see each suite's own header comment
# for what it actually spends its time on. Override per-invocation with
# E2E_SUITE_TIMEOUT_SECONDS if a slower environment needs more room.
suite_timeout="${E2E_SUITE_TIMEOUT_SECONDS:-1800}"

declare -a requested=("$@")
declare -a suite_paths=()
if [[ ${#requested[@]} -eq 0 ]]; then
  while IFS= read -r path; do
    suite_paths+=("$path")
  done < <(find "$suites_dir" -maxdepth 1 -name '*.sh' | sort)
else
  for name in "${requested[@]}"; do
    name="${name%.sh}"
    path="$suites_dir/$name.sh"
    [[ -f "$path" ]] || { echo "run.sh: no such suite: $name (looked for $path)" >&2; exit 1; }
    suite_paths+=("$path")
  done
fi

[[ ${#suite_paths[@]} -gt 0 ]] || { echo "run.sh: no suites found in $suites_dir" >&2; exit 1; }

echo "== E2E run $E2E_RUN_ID: ${#suite_paths[@]} suite(s), ${suite_timeout}s each =="

overall_start=$(date +%s)
for path in "${suite_paths[@]}"; do
  name="$(basename "$path" .sh)"
  echo
  echo "===== running suite: $name (timeout ${suite_timeout}s) ====="
  start=$(date +%s)
  if timeout "${suite_timeout}s" bash "$path"; then
    elapsed=$(( $(date +%s) - start ))
    echo "===== suite $name PASSED (${elapsed}s) ====="
  else
    status=$?
    elapsed=$(( $(date +%s) - start ))
    if [[ "$status" -eq 124 ]]; then
      echo "===== suite $name TIMED OUT after ${suite_timeout}s =====" >&2
    else
      echo "===== suite $name FAILED after ${elapsed}s (exit $status) =====" >&2
    fi
    exit "$status"
  fi
done

overall_elapsed=$(( $(date +%s) - overall_start ))
echo
echo "== all ${#suite_paths[@]} suite(s) passed in ${overall_elapsed}s =="
